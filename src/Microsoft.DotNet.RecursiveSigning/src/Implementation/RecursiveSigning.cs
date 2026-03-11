// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.DotNet.RecursiveSigning.Abstractions;
using Microsoft.DotNet.RecursiveSigning.Models;

namespace Microsoft.DotNet.RecursiveSigning.Implementation
{
    /// <summary>
    /// Main orchestrator for the recursive signing workflow.
    /// Implements the three-phase algorithm: Discovery → Iterative Signing → Finalization.
    /// </summary>
    public sealed class RecursiveSigning : IRecursiveSigning
    {
        private readonly IFileSystem _fileSystem;
        private readonly IReadOnlyList<IFileAnalyzer> _fileAnalyzers;
        private readonly ICertificateCalculator _signatureCalculator;
        private readonly IReadOnlyList<IContainerHandler> _containerHandlers;
        private readonly ISigningProvider _signingProvider;
        private readonly IFileDeduplicator _fileDeduplicator;
        private readonly ILogger<RecursiveSigning> _logger;

        // Per-operation state, initialized at the start of each SignAsync call.
        private ISigningGraph _signingGraph = null!;

        public RecursiveSigning(
            IFileSystem fileSystem,
            IEnumerable<IFileAnalyzer> fileAnalyzers,
            ICertificateCalculator signatureCalculator,
            IEnumerable<IContainerHandler> containerHandlers,
            ISigningProvider signingProvider,
            IFileDeduplicator fileDeduplicator,
            ILogger<RecursiveSigning> logger)
        {
            _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
            _fileAnalyzers = (fileAnalyzers ?? throw new ArgumentNullException(nameof(fileAnalyzers))).ToList();
            _signatureCalculator = signatureCalculator ?? throw new ArgumentNullException(nameof(signatureCalculator));
            _containerHandlers = (containerHandlers ?? throw new ArgumentNullException(nameof(containerHandlers))).ToList();
            _signingProvider = signingProvider ?? throw new ArgumentNullException(nameof(signingProvider));
            _fileDeduplicator = fileDeduplicator ?? throw new ArgumentNullException(nameof(fileDeduplicator));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Executes the full recursive signing workflow.
        /// </summary>
        /// <param name="request">Signing request containing input files, configuration, and options.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Signing result with signed files, errors, and telemetry.</returns>
        public async Task<SigningResult> SignAsync(SigningRequest request, CancellationToken cancellationToken = default)
        {
            // Create fresh per-operation state.
            _signingGraph = new SigningGraph();

            var sw = Stopwatch.StartNew();
            var errors = new List<SigningError>();
            var effectiveInputFiles = ResolveRootInputs(request.InputFiles, request.OutputDirectory);
            var effectiveRequest = new SigningRequest(effectiveInputFiles, request.TempDirectory, request.Options, request.OutputDirectory);

            // Build the input→output mapping for FileResults tracking.
            // The two lists are parallel: request.InputFiles[i] maps to effectiveInputFiles[i].
            var inputOutputMapping = new List<(string originalPath, string effectivePath)>(request.InputFiles.Count);
            for (int i = 0; i < request.InputFiles.Count; i++)
            {
                inputOutputMapping.Add((request.InputFiles[i].ToString(), effectiveInputFiles[i].ToString()));
            }

            try
            {
                _logger.LogInformation("Starting recursive signing for {FileCount} input files", effectiveRequest.InputFiles.Count);

                // Phase 1: Discovery - Build the signing graph
                _logger.LogInformation("Phase 1: Discovery and Analysis");
                var discoverySw = Stopwatch.StartNew();
                await DiscoveryPhaseAsync(effectiveRequest, errors, cancellationToken);

                _signingGraph.FinalizeDiscovery();
                discoverySw.Stop();

                if (errors.Count > 0)
                {
                    _logger.LogError("Discovery phase failed with {ErrorCount} errors", errors.Count);
                    return CreateResult(false, errors, sw.Elapsed, 0, 0,
                        discoverySw.Elapsed, TimeSpan.Zero, TimeSpan.Zero, new List<SigningRoundTelemetry>(), 0,
                        BuildFileResults(inputOutputMapping));
                }

                var allNodes = _signingGraph.GetAllNodes();
                _logger.LogInformation("Discovered {NodeCount} files total", allNodes.Count);

                // Log skip/sign-regardless decisions for diagnosability
                foreach (var node in allNodes.OfType<FileNode>())
                {
                    if (node.State == FileNodeState.Skipped && node.CertificateIdentifier != null && node.Metadata.IsAlreadySigned)
                    {
                        _logger.LogInformation("Skipping '{FileName}': already signed (would use certificate '{CertName}' if unsigned)",
                            node.ContentKey.FileName, node.CertificateIdentifier.Name);
                    }
                    else if (node.Metadata.IsAlreadySigned && node.CertificateIdentifier?.AlwaysSign == true)
                    {
                        _logger.LogInformation("Signing '{FileName}' despite existing signature (certificate '{CertName}' has alwaysSign=true)",
                            node.ContentKey.FileName, node.CertificateIdentifier.Name);
                    }
                }

                // Phase 2: Iterative Signing
                _logger.LogInformation("Phase 2: Iterative Signing");
                var signingSw = Stopwatch.StartNew();
                var roundTelemetry = new List<SigningRoundTelemetry>();
                await IterativeSigningPhaseAsync(effectiveRequest, errors, roundTelemetry, cancellationToken);
                signingSw.Stop();

                int duplicateCount = allNodes.OfType<ReferenceNode>().Count();

                if (errors.Count > 0)
                {
                    _logger.LogError("Signing phase failed with {ErrorCount} errors", errors.Count);
                    return CreateResult(false, errors, sw.Elapsed, 0, allNodes.Count,
                        discoverySw.Elapsed, signingSw.Elapsed, TimeSpan.Zero, roundTelemetry, duplicateCount,
                        BuildFileResults(inputOutputMapping));
                }

                // Phase 3: Finalization
                _logger.LogInformation("Phase 3: Finalization");
                var finalizationSw = Stopwatch.StartNew();
                FinalizationPhase(errors);
                finalizationSw.Stop();

                sw.Stop();
                bool success = errors.Count == 0;

                // Compute counts from graph state
                int uniqueFilesSigned = _signingGraph.GetAllNodes().OfType<FileNode>()
                    .Count(n => n.State == FileNodeState.Complete);

                _logger.LogInformation(
                    "Signing completed in {Duration}ms. Success: {Success}, Unique files signed: {SignedCount}/{TotalCount}",
                    sw.ElapsedMilliseconds, success, uniqueFilesSigned, allNodes.Count);

                return CreateResult(success, errors, sw.Elapsed, uniqueFilesSigned, allNodes.Count,
                    discoverySw.Elapsed, signingSw.Elapsed, finalizationSw.Elapsed, roundTelemetry, duplicateCount,
                    BuildFileResults(inputOutputMapping));
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Signing operation was cancelled");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during signing");
                errors.Add(new SigningError($"Unexpected error: {ex.Message}", exception: ex));
                return CreateResult(false, errors, sw.Elapsed, 0, 0,
                    TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, new List<SigningRoundTelemetry>(), 0,
                    BuildFileResults(inputOutputMapping));
            }
        }

        private async Task DiscoveryPhaseAsync(
            SigningRequest request,
            List<SigningError> errors,
            CancellationToken cancellationToken)
        {
            foreach (var filePath in request.InputFiles.Select(f => f.ToString()))
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    await TrackFile(filePath, null, request.TempDirectory, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error discovering file: {FilePath}", filePath);
                    errors.Add(new SigningError($"Error discovering file: {ex.Message}", filePath, ex));
                }
            }
        }


        /// <summary>
        /// Tracks a top-level file from disk, performing deduplication, analysis, and optional container discovery.
        /// </summary>
        /// <param name="filePath">Path to the file on disk.</param>
        /// <param name="parentNode">Optional parent node if the file is contained within another container.</param>
        /// <param name="tempDirectory">Temporary directory for intermediate files.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The node representing the tracked file.</returns>
        private async Task<FileNodeBase> TrackFile(
            string filePath,
            FileNode? parentNode,
            string tempDirectory,
            CancellationToken cancellationToken)
        {
            // If the file does not exist, then throw
            if (!_fileSystem.FileExists(filePath))
            {
                throw new FileNotFoundException("Input file not found", filePath);
            }

            // Compute identity + location locally and ask analyzer only for intrinsic metadata
            string fileName = Path.GetFileName(filePath);
            using var stream = _fileSystem.GetFileStream(filePath, FileMode.Open, FileAccess.Read);
            ContentHash contentHash = await ContentHash.FromStreamAsync(stream, cancellationToken);
            var contentKey = new FileContentKey(contentHash, fileName);
            var location = new FileLocation(filePath, RelativePathInContainer: null);

            // Check for duplicates and skip discovery 
            if (_fileDeduplicator.TryGetRegisteredFile(contentKey, out string? originalPath))
            {
                _logger.LogDebug(
                    "Duplicate file detected: {FileName} at {FilePath} (original: {OriginalPath}), skipping analysis and extraction",
                    contentKey.FileName,
                    filePath,
                    originalPath);

                return CreateReferenceNode(contentKey, location, parentNode, "file", filePath);
            }

            _fileDeduplicator.RegisterFile(contentKey, filePath);

            var metadata = await AnalyzeFileAsync(filePath, cancellationToken);

            // First occurrence: delegate to DiscoverFileAsync for full analysis
            return await DiscoverFileAsync(contentKey, location, metadata, parentNode, tempDirectory, cancellationToken);
        }

        /// <summary>
        /// Tracks a file whose contents are provided as a stream (typically extracted from a container).
        /// Performs deduplication, analysis, extraction to disk, and optional container discovery.
        /// </summary>
        /// <param name="contentStream">Stream containing the file content.</param>
        /// <param name="relativePath">Relative path of the file within its container.</param>
        /// <param name="parentNode">Container node that owns this entry.</param>
        /// <param name="tempDirectory">Temporary directory for intermediate files.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The node representing the tracked file.</returns>
        private async Task<FileNodeBase> TrackNestedFile(
            Stream contentStream,
            string relativePath,
            FileNode parentNode,
            string tempDirectory,
            CancellationToken cancellationToken)
        {
            if (contentStream == null)
            {
                throw new ArgumentNullException(nameof(contentStream));
            }

            if (string.IsNullOrWhiteSpace(relativePath))
            {
                throw new ArgumentException("Relative path cannot be null or empty", nameof(relativePath));
            }

            if (parentNode == null)
            {
                throw new ArgumentNullException(nameof(parentNode));
            }

            // Extract filename from relative path
            string fileName = Path.GetFileName(relativePath);

            // Compute identity locally and ask analyzer only for intrinsic metadata
            ContentHash contentHash = await ContentHash.FromStreamAsync(contentStream, cancellationToken);
            var contentKey = new FileContentKey(contentHash, fileName);

            // Register and check for duplicates BEFORE analyzing or writing to disk
            // If the content has been seen before, reuse the first extracted path.
            if (_fileDeduplicator.TryGetRegisteredFile(contentKey, out string? originalPath))
            {
                _logger.LogDebug(
                    "Duplicate file detected in container: {FileName} [{ContentHash}] at {RelativePath} (original: {OriginalPath}), skipping extraction",
                    contentKey.FileName,
                    ShortHash(contentKey.ContentHash),
                    relativePath,
                    originalPath);

                var referenceLocation = new FileLocation(originalPath, relativePath);
                return CreateReferenceNodeForContainer(contentKey, referenceLocation, parentNode);
            }

            var metadata = await AnalyzeFileAsync(contentStream, fileName, cancellationToken);

            // First occurrence: write stream to disk and register it
            string filePath = await WriteStreamToTempFileAsync(
                contentStream,
                relativePath,
                tempDirectory,
                cancellationToken);

            _fileDeduplicator.RegisterFile(contentKey, filePath);

            return await DiscoverFileAsync(contentKey, new FileLocation(filePath, relativePath), metadata, parentNode, tempDirectory, cancellationToken);
        }

        /// <summary>
        /// Creates a reference node for a duplicate file (non-container context).
        /// </summary>
        private FileNodeBase CreateReferenceNode(FileContentKey contentKey, FileLocation fileLocation, FileNode? parentNode, string context, string location)
        {
            var existingNode = FindExistingNodeByContentKey(contentKey);
            if (existingNode == null)
            {
                throw new InvalidOperationException(
                    $"Duplicate detected but no existing node found for content key {contentKey}. This indicates a bug in the deduplication logic.");
            }

            // Create a reference node that shares the same certificate identifier
            // but tracks this specific location in the container hierarchy
            var referenceNode = new ReferenceNode(contentKey, fileLocation, existingNode);
            _signingGraph.AddNode(referenceNode, parentNode);
            
            _logger.LogDebug("Created reference node for duplicate {Context} [{ContentHash}] at: {Location}", context, ShortHash(contentKey.ContentHash), location);
            return referenceNode;
        }

        /// <summary>
        /// Creates a reference node for a duplicate file found in a container.
        /// </summary>
        private FileNodeBase CreateReferenceNodeForContainer(FileContentKey contentKey, FileLocation fileLocation, FileNode parentNode)
        {
            var existingNode = FindExistingNodeByContentKey(contentKey);
            if (existingNode == null)
            {
                throw new InvalidOperationException(
                    $"Duplicate detected but no existing node found for content key {contentKey}. This indicates a bug in the deduplication logic.");
            }

            // Create a reference node for this container location.
            // Keep the original file location (container path + relative path) so the graph structure is correct.
            // The canonical node carries the real on-disk bytes for signing.
            var referenceNode = new ReferenceNode(contentKey, fileLocation, existingNode);
            _signingGraph.AddNode(referenceNode, parentNode);
            
            _logger.LogDebug(
                "Created reference node for duplicate file in container [{ContentHash}] at: {RelativePath}",
                ShortHash(contentKey.ContentHash),
                fileLocation.RelativePathInContainer);
            return referenceNode;
        }

        /// <summary>
        /// Writes a stream to a temporary file on disk.
        /// </summary>
        private async Task<string> WriteStreamToTempFileAsync(
            Stream contentStream,
            string relativePath,
            string tempDirectory,
            CancellationToken cancellationToken)
        {
            string extractDir = _fileSystem.PathCombine(tempDirectory, Guid.NewGuid().ToString());
            _fileSystem.CreateDirectory(extractDir);
            string filePath = _fileSystem.PathCombine(extractDir, relativePath.Replace('/', Path.DirectorySeparatorChar));
            
            var fileDir = _fileSystem.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(fileDir))
            {
                _fileSystem.CreateDirectory(fileDir);
            }

            // Write stream to disk
            using (var fileStream = _fileSystem.GetFileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                await contentStream.CopyToAsync(fileStream, cancellationToken);
            }

            return filePath;
        }

        /// <summary>
        /// Finds an existing node in the signing graph that matches the given content key.
        /// </summary>
        /// <param name="contentKey">File content key to locate.</param>
        /// <returns>The first matching node, or null if not found.</returns>
        private FileNode? FindExistingNodeByContentKey(FileContentKey contentKey)
        {
            var allNodes = _signingGraph.GetAllNodes();
            return allNodes.OfType<FileNode>().FirstOrDefault(n => n.ContentKey.Equals(contentKey));
        }

        /// <summary>
        /// Discovers signing information for a file and, if it is a container, recursively discovers its contents.
        /// </summary>
        /// <param name="contentKey">Content identity of the file.</param>
        /// <param name="location">File location information (path on disk and optional relative path in container).</param>
        /// <param name="metadata">Analyzed file metadata.</param>
        /// <param name="parentNode">Optional parent node if the file is contained within another container.</param>
        /// <param name="tempDirectory">Temporary directory for intermediate files.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The discovered node.</returns>
        private async Task<FileNode> DiscoverFileAsync(
            FileContentKey contentKey,
            FileLocation location,
            IFileMetadata metadata,
            FileNode? parentNode,
            string tempDirectory,
            CancellationToken cancellationToken)
        {
            // First occurrence: full analysis and potential container extraction
            _logger.LogDebug(
                "Analyzing new file: {FileName} [{ContentHash}] at {FilePath} (parent container: {ParentContainer})",
                contentKey.FileName,
                ShortHash(contentKey.ContentHash),
                location.FilePathOnDisk,
                parentNode?.ContentKey.FileName ?? "<root>");

            var certificateIdentifier = _signatureCalculator.CalculateCertificateIdentifier(metadata);

            // Create node
            var node = new FileNode(contentKey, location, metadata, certificateIdentifier);
            _signingGraph.AddNode(node, parentNode);

            // Check if there's a handler that can unpack this file (determines if it's a container)
            IContainerHandler? handler;
            try
            {
                handler = FindHandler(location.FilePathOnDisk!);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error selecting container handler for file: {FilePath}", location.FilePathOnDisk);
                handler = null;
            }
            bool isContainer = handler != null;

            // Node state is graph-owned and computed when the graph is built.

            _logger.LogDebug("Discovered file: {FileName} [{ContentHash}], IsAlreadySigned: {IsAlreadySigned}, Certificate: {Certificate}, IsContainer: {IsContainer}",
                contentKey.FileName, ShortHash(contentKey.ContentHash), metadata.IsAlreadySigned, certificateIdentifier?.Name ?? "<none>", isContainer);

            // If this is a container (has a registered handler), recursively discover its contents
            if (isContainer)
            {
                await DiscoverContainerContentsAsync(node, handler!, tempDirectory, cancellationToken);
            }

            return node;
        }

        /// <summary>
        /// Enumerates entries in a container and tracks each entry as a child node.
        /// </summary>
        /// <param name="containerNode">Container node whose contents should be discovered.</param>
        /// <param name="handler">Handler used to read entries from the container.</param>
        /// <param name="tempDirectory">Temporary directory for intermediate files.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        private async Task DiscoverContainerContentsAsync(
            FileNode containerNode,
            IContainerHandler handler,
            string tempDirectory,
            CancellationToken cancellationToken)
        {
            _logger.LogDebug("Discovering contents of container: {FileName} [{ContentHash}]", containerNode.ContentKey.FileName, ShortHash(containerNode.ContentKey.ContentHash));

            await foreach (var entry in handler.ReadEntriesAsync(containerNode.Location.FilePathOnDisk!, tempDirectory, cancellationToken))
            {
                using (entry)
                {
                    await TrackNestedFile(entry.ContentStream!, entry.RelativePath, containerNode, tempDirectory, cancellationToken);
                }
            }
        }

        /// <summary>
        /// Performs iterative signing rounds until all nodes are signed or no further progress can be made.
        /// </summary>
        /// <param name="request">Signing request.</param>
        /// <param name="errors">Accumulated error list.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        private async Task IterativeSigningPhaseAsync(
            SigningRequest request,
            List<SigningError> errors,
            List<SigningRoundTelemetry> roundTelemetry,
            CancellationToken cancellationToken)
        {
            int roundNumber = 0;

            while (!_signingGraph.IsComplete())
            {
                cancellationToken.ThrowIfCancellationRequested();

                bool madeProgress = false;
                var roundInfo = new SigningRoundTelemetry { RoundNumber = roundNumber };

                var toSign = _signingGraph.GetNodesReadyForSigning();
                if (toSign.Count > 0)
                {
                    _logger.LogInformation("Signing round {Round}: {FileCount} file(s) ready", roundNumber, toSign.Count);
                    var signSw = Stopwatch.StartNew();
                    bool signedAny = await SignRoundAsync(toSign, request, errors, cancellationToken);
                    signSw.Stop();
                    roundInfo.SigningDuration = signSw.Elapsed;
                    roundInfo.FilesSigned = toSign.Count;
                    madeProgress |= signedAny;
                }

                var toRepack = _signingGraph.GetContainersReadyForRepack();
                if (toRepack.Count > 0)
                {
                    _logger.LogInformation("Repack round {Round}: {FileCount} container(s) ready", roundNumber, toRepack.Count);
                    var repackSw = Stopwatch.StartNew();
                    await RepackContainersAsync(toRepack, request.TempDirectory, errors, cancellationToken);
                    repackSw.Stop();
                    roundInfo.RepackDuration = repackSw.Elapsed;

                    madeProgress = true;

                    // Repacked containers are now ready to be signed in the next iteration.
                    foreach (var container in toRepack)
                    {
                        if (container.State == FileNodeState.ReadyToRepack)
                        {
                            _signingGraph.MarkContainerAsRepacked(container);
                            madeProgress = true;
                        }
                    }
                }

                // If we made no progress, the graph is stuck.
                if (!madeProgress)
                {
                    if (_signingGraph.IsComplete())
                    {
                        break;
                    }

                    errors.Add(new SigningError("Signing graph has no ready nodes but is not complete. Possible circular dependency. Last signing provider errors: " + string.Join(", ", errors.Where(e => e.Message.Contains("Signing provider failed")))));
                    break;
                }

                roundTelemetry.Add(roundInfo);
                roundNumber++;
            }
        }

        /// <summary>
        /// Repacks containers whose children have been signed, updating their identity and metadata.
        /// </summary>
        /// <param name="containers">Containers ready for repack.</param>
        /// <param name="errors">Accumulated error list.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        private async Task RepackContainersAsync(
            IReadOnlyList<FileNode> containers,
            string tempDirectory,
            List<SigningError> errors,
            CancellationToken cancellationToken)
        {
            foreach (var container in containers)
            {
                try
                {
                    string repackedPath = await RepackContainerAsync(container, tempDirectory, cancellationToken);

                    using (var repackedStream = _fileSystem.GetFileStream(repackedPath, FileMode.Open, FileAccess.Read))
                    {
                        ContentHash repackedHash = await ContentHash.FromStreamAsync(repackedStream, cancellationToken);
                        container.ContentKey = new FileContentKey(repackedHash, container.ContentKey.FileName);
                    }

                    container.Location = new FileLocation(repackedPath, container.Location.RelativePathInContainer);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error repacking container: {FilePath}", container.Location.FilePathOnDisk);
                    errors.Add(new SigningError($"Error repacking container: {ex.Message}", container.Location.FilePathOnDisk, ex));
                }
            }
        }

        /// <summary>
        /// Signs nodes that are ready for signing, deduplicating by content key and reusing signed outputs.
        /// </summary>
        /// <param name="nodes">Nodes ready for signing.</param>
        /// <param name="request">Signing request.</param>
        /// <param name="errors">Accumulated error list.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        private async Task<bool> SignRoundAsync(
            IReadOnlyList<FileNode> nodes,
            SigningRequest request,
            List<SigningError> errors,
            CancellationToken cancellationToken)
        {
            var filesToSign = new List<(FileNode node, string outputPath)>();

            foreach (var node in nodes)
            {
                // Sign in place. Optional root output copies are handled after signing.
                filesToSign.Add((node, node.Location.FilePathOnDisk!));
            }

            if (filesToSign.Count == 0)
            {
                return false;
            }

            // Call signing provider (only signs first occurrence of each content key)
            _logger.LogDebug("Signing {Count} unique file(s)", filesToSign.Count);
            bool success = await _signingProvider.SignFilesAsync(filesToSign, cancellationToken);

            if (!success)
            {
                _logger.LogError("Signing provider returned failure for {Count} file(s)", filesToSign.Count);
                errors.Add(new SigningError($"Signing provider failed for {filesToSign.Count} files"));
                return false;
            }

            // Mark first occurrences as signed and register signed versions
            foreach (var (node, outputPath) in filesToSign)
            {
                _signingGraph.MarkAsComplete(node);
                _fileDeduplicator.RegisterSignedFile(node.ContentKey, outputPath);
            }

            return true;
        }

        /// <summary>
        /// Repacks a container by writing out a new container file from its (signed) child entries.
        /// </summary>
        /// <param name="containerNode">Container node to repack.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Path to the repacked container on disk.</returns>
        private async Task<string> RepackContainerAsync(FileNode containerNode, string tempDirectory, CancellationToken cancellationToken)
        {
            var handler = FindHandler(containerNode.Location.FilePathOnDisk!);
            if (handler == null)
            {
                throw new InvalidOperationException($"No handler found for repacking container: {containerNode.Location.FilePathOnDisk}");
            }

            _logger.LogDebug("Repacking container: {FileName} [{ContentHash}]", containerNode.ContentKey.FileName, ShortHash(containerNode.ContentKey.ContentHash));

            // Build list of entries with signed versions
            var entries = new List<ContainerEntry>();

            foreach (var child in containerNode.Children.OfType<FileNode>())
            {
                // Get signed version
                if (!_fileDeduplicator.TryGetSignedVersion(child.ContentKey, out string? signedPath))
                {
                    signedPath = child.Location.FilePathOnDisk!; // Use original if not signed
                }

                var stream = _fileSystem.GetFileStream(signedPath!, FileMode.Open, FileAccess.Read);
                var entry = new ContainerEntry(child.Location.RelativePathInContainer!, stream)
                {
                    UpdatedContentPath = signedPath
                };
                entries.Add(entry);
            }

            string repackedPath = containerNode.Location.FilePathOnDisk!;

            // Repack container in place.
            await handler.WriteContainerAsync(
                repackedPath,
                entries,
                new ContainerMetadata(),
                tempDirectory,
                cancellationToken);

            // Cleanup entry streams
            foreach (var entry in entries)
            {
                entry.Dispose();
            }

            return repackedPath;
        }

        /// <summary>
        /// Performs final verification and reporting after signing.
        /// </summary>
        /// <param name="errors">Accumulated error list.</param>
        private void FinalizationPhase(List<SigningError> errors)
        {
            // Phase 3 tasks:
            // - Generate report

            var allNodes = _signingGraph.GetAllNodes();

            var unsignedNodes = allNodes.OfType<FileNode>().Where(n => n.State != FileNodeState.Complete && n.State != FileNodeState.Skipped).ToList();

            if (unsignedNodes.Count > 0)
            {
                _logger.LogWarning("{Count} files were not signed", unsignedNodes.Count);
                foreach (var node in unsignedNodes)
                {
                    errors.Add(new SigningError($"File was not signed", node.Location.FilePathOnDisk));
                }
            }

            int signedCount = _signingGraph.GetSignedNodes().OfType<FileNode>().Count();
            _logger.LogInformation("Finalization complete. Signed: {SignedCount}, Skipped: {SkippedCount}, Errors: {ErrorCount}",
                signedCount,
                allNodes.OfType<FileNode>().Count(n => n.State == FileNodeState.Skipped),
                errors.Count);
        }

        /// <summary>
        /// Resolves the root input set for processing.
        /// When an output directory is configured, root inputs are copied there first and the copied paths are returned.
        /// </summary>
        private IReadOnlyList<FileInfo> ResolveRootInputs(IReadOnlyList<FileInfo> inputFiles, string? outputDirectory)
        {
            if (outputDirectory is null)
            {
                return inputFiles;
            }

            var sourcePaths = inputFiles.Select(f => f.ToString()).ToArray();
            string commonRoot = RootInputOutputPathHelper.GetCommonRootForFiles(sourcePaths);

            var relocatedInputs = new List<FileInfo>(sourcePaths.Length);
            foreach (string sourcePath in sourcePaths)
            {
                string destinationPath = BuildOutputPath(sourcePath, outputDirectory, commonRoot);
                CopyToOutputPath(sourcePath, destinationPath);
                relocatedInputs.Add(new FileInfo(destinationPath));
            }

            return relocatedInputs;
        }

        /// <summary>
        /// Builds the destination path for a root input under the configured output directory
        /// using the shared common root of all root inputs.
        /// </summary>
        private static string BuildOutputPath(string sourcePath, string outputDirectory, string commonRoot)
        {
            return RootInputOutputPathHelper.BuildOutputPath(sourcePath, outputDirectory, commonRoot);
        }

        private void CopyToOutputPath(string sourcePath, string destinationPath)
        {
            if (string.Equals(sourcePath, destinationPath, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            string? destinationDirectory = _fileSystem.GetDirectoryName(destinationPath);
            if (!string.IsNullOrEmpty(destinationDirectory))
            {
                _fileSystem.CreateDirectory(destinationDirectory);
            }

            _fileSystem.CopyFile(sourcePath, destinationPath, overwrite: true);
        }

        private static string ShortHash(ContentHash contentHash)
        {
            string hex = contentHash.ToHexString();
            return hex.Length <= 8 ? hex : hex.Substring(0, 8);
        }

        /// <summary>
        /// Finds the container handler for the given file path.
        /// Returns null if no handler matches. Throws if more than one handler matches.
        /// </summary>
        private IContainerHandler? FindHandler(string filePath)
        {
            IContainerHandler? match = null;
            foreach (var handler in _containerHandlers)
            {
                if (handler.CanHandle(filePath))
                {
                    if (match != null)
                    {
                        throw new InvalidOperationException(
                            $"More than one container handler can handle file '{filePath}'.");
                    }
                    match = handler;
                }
            }
            return match;
        }

        /// <summary>
        /// Analyzes a file on disk using the first matching registered analyzer.
        /// Falls back to basic filename-only metadata when no analyzer matches.
        /// </summary>
        private async Task<IFileMetadata> AnalyzeFileAsync(string filePath, CancellationToken cancellationToken)
        {
            string fileName = Path.GetFileName(filePath);
            foreach (var analyzer in _fileAnalyzers)
            {
                if (analyzer.CanAnalyze(fileName))
                {
                    return await analyzer.AnalyzeAsync(filePath, cancellationToken);
                }
            }

            // No analyzer matched. Zero-length files cannot be signed.
            bool canBeSigned = _fileSystem.GetFileLength(filePath) > 0;
            return new FileMetadata(fileName, canBeSigned: canBeSigned);
        }

        /// <summary>
        /// Analyzes a stream using the first matching registered analyzer.
        /// Falls back to basic filename-only metadata when no analyzer matches.
        /// </summary>
        private async Task<IFileMetadata> AnalyzeFileAsync(Stream contentStream, string fileName, CancellationToken cancellationToken)
        {
            foreach (var analyzer in _fileAnalyzers)
            {
                if (analyzer.CanAnalyze(fileName))
                {
                    return await analyzer.AnalyzeAsync(contentStream, fileName, cancellationToken);
                }
            }

            // No analyzer matched. Zero-length streams cannot be signed.
            bool canBeSigned = contentStream.Length > 0;
            return new FileMetadata(fileName, canBeSigned: canBeSigned);
        }

        /// <summary>
        /// Creates a <see cref="SigningResult" /> object from the accumulated workflow state.
        /// </summary>
        /// <param name="success">Overall success flag.</param>
        /// <param name="errors">Error list.</param>
        /// <param name="duration">Total duration.</param>
        /// <param name="uniqueFilesSigned">Count of unique files signed.</param>
        /// <param name="totalFiles">Total file count discovered.</param>
        /// <returns>Signing result.</returns>
        private SigningResult CreateResult(
            bool success,
            List<SigningError> errors,
            TimeSpan duration,
            int uniqueFilesSigned,
            int totalFiles,
            TimeSpan discoveryDuration,
            TimeSpan signingDuration,
            TimeSpan finalizationDuration,
            List<SigningRoundTelemetry> rounds,
            int duplicateFiles,
            List<FileResult>? fileResults = null)
        {
            var telemetry = new SigningTelemetry
            {
                TotalFiles = totalFiles,
                UniqueFilesSigned = uniqueFilesSigned,
                FilesSkipped = _signingGraph.GetSkippedNodes().Count,
                DuplicateFiles = duplicateFiles,
                SigningRounds = rounds.Count,
                Duration = duration,
                DiscoveryDuration = discoveryDuration,
                SigningDuration = signingDuration,
                FinalizationDuration = finalizationDuration,
                Rounds = rounds,
            };

            return new SigningResult(success, errors, telemetry, fileResults, _signingGraph);
        }

        /// <summary>
        /// Builds file result entries mapping each original input to its effective output path
        /// and whether the file was updated (signed or repacked) during the workflow.
        /// </summary>
        private List<FileResult> BuildFileResults(List<(string originalPath, string effectivePath)> inputOutputMapping)
        {
            var allNodes = _signingGraph.GetAllNodes();

            // Index root-level nodes (no parent) by their on-disk path for fast lookup.
            var rootNodesByPath = new Dictionary<string, FileNodeBase>(StringComparer.OrdinalIgnoreCase);
            foreach (var node in allNodes)
            {
                if (node.Parent == null && node.Location.FilePathOnDisk != null)
                {
                    rootNodesByPath[node.Location.FilePathOnDisk] = node;
                }
            }

            var results = new List<FileResult>(inputOutputMapping.Count);
            foreach (var (originalPath, effectivePath) in inputOutputMapping)
            {
                bool wasUpdated = false;
                if (rootNodesByPath.TryGetValue(effectivePath, out var node))
                {
                    // A node is "updated" if it reached Complete state (was signed or repacked+signed).
                    // ReferenceNodes that resolved to a signed canonical are also considered updated.
                    if (node is FileNode fileNode)
                    {
                        wasUpdated = fileNode.State == FileNodeState.Complete;
                    }
                    else if (node is ReferenceNode refNode)
                    {
                        wasUpdated = refNode.CanonicalNode.State == FileNodeState.Complete;
                    }
                }

                results.Add(new FileResult(originalPath, effectivePath, wasUpdated));
            }

            return results;
        }
    }
}

