// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.IO.Compression;
using System.IO.Packaging;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Build.Framework;
using TaskLoggingHelper = Microsoft.Build.Utilities.TaskLoggingHelper;

namespace Microsoft.DotNet.SignTool
{
    /// <summary>
    /// Data for a zip container. Can refer to any zip format such as VSIX, NuPkg, or a raw zip archive.
    /// </summary>
    internal sealed class ZipData
    {
        /// <summary>
        /// Signing information.
        /// </summary>
        internal FileInfo ZipFileInfo { get; }

        /// <summary>
        /// The parts inside this container which may need to be signed.
        /// </summary>
        internal ImmutableDictionary<string, ZipPart> NestedParts { get; }

        internal ZipData(FileInfo fileInfo, ImmutableDictionary<string, ZipPart> nestedBinaryParts)
        {
            ZipFileInfo = fileInfo;
            NestedParts = nestedBinaryParts;
        }

        internal ZipPart? FindNestedPart(string relativeName)
        {
            if (NestedParts.TryGetValue(relativeName, out ZipPart part))
            {
                return part;
            }

            return null;
        }

        /// <summary>
        /// Repack the zip container with the signed files.
        /// </summary>
        public async Task Repack(TaskLoggingHelper log, ConcurrentDictionary<FileContentKey, Task> signingTasksByContentKey, string tempDir = null, string wixToolsPath = null)
        {
#if NET472
            if (ZipFileInfo.IsVsix())
            {
                await RepackPackageAsync(log, signingTasksByContentKey);
            }
            else
#endif
            {
                if (ZipFileInfo.IsWixContainer())
                {
                    await RepackWixPack(log, signingTasksByContentKey, tempDir, wixToolsPath);
                }
                else 
                {
                    await RepackRawZip(log, signingTasksByContentKey);
                }
            }
        }

#if NET472
        /// <summary>
        /// Repack a zip container with a package structure.
        /// </summary>
        private async Task RepackPackageAsync(TaskLoggingHelper log, ConcurrentDictionary<FileContentKey, Task> entryReadyMap)
        {
            string getPartRelativeFileName(PackagePart part)
            {
                var path = part.Uri.OriginalString;
                if (!string.IsNullOrEmpty(path) && path[0] == '/')
                {
                    path = path.Substring(1);
                }

                return path;
            }
            
            using (var package = Package.Open(ZipFileInfo.File.FullPath, FileMode.Open, FileAccess.ReadWrite))
            {
                // Before doing this, we need to ensure that all the files we are about to repack
                // are signed.
                List<PackagePart> partsToRepack = new List<PackagePart>();
                List<Task> signingTasksToWaitOn = new List<Task>();
                foreach (var part in package.GetParts())
                {
                    var relativeName = getPartRelativeFileName(part);
                    var zipPart = FindNestedPart(relativeName);
                    if (!zipPart.HasValue)
                    {
                        continue;
                    }
                    partsToRepack.Add(part);
                    if (entryReadyMap.TryGetValue(zipPart.Value.FileInfo.FileContentKey, out var task))
                    {
                        signingTasksToWaitOn.Add(task);
                    }
                }

                await Task.WhenAll(signingTasksToWaitOn);

                foreach (var part in partsToRepack)
                {
                    var relativeName = getPartRelativeFileName(part);
                    var signedPart = FindNestedPart(relativeName);

                    using (var signedStream = File.OpenRead(signedPart.Value.FileInfo.File.FullPath))
                    using (var partStream = part.GetStream(FileMode.Open, FileAccess.ReadWrite))
                    {
                        log.LogMessage(MessageImportance.Low, $"Copying signed stream from {signedPart.Value.FileInfo.File.FullPath} to {ZipFileInfo.File.FullPath} -> {relativeName}.");

                        await signedStream.CopyToAsync(partStream);
                        partStream.SetLength(signedStream.Length);
                    }
                }
            }
        }
#endif

        /// <summary>
        /// Repack raw zip container.
        /// </summary>
        private async Task RepackRawZip(TaskLoggingHelper log, ConcurrentDictionary<FileContentKey, Task> entryReadyMap)
        {
            using (var archive = new ZipArchive(File.Open(ZipFileInfo.File.FullPath, FileMode.Open), ZipArchiveMode.Update))
            {
                // Before doing this, we need to ensure that all the files we are about to repack
                // are signed.
                List<ZipArchiveEntry> entriesToRepack = new List<ZipArchiveEntry>();
                List<Task> entryReadyTasks = new List<Task>();
                foreach (var entry in archive.Entries)
                {
                    var relativeName = entry.FullName;
                    var zipPart = FindNestedPart(relativeName);
                    if (!zipPart.HasValue)
                    {
                        continue;
                    }
                    entriesToRepack.Add(entry);
                    if (entryReadyMap.TryGetValue(zipPart.Value.FileInfo.FileContentKey, out var task))
                    {
                        entryReadyTasks.Add(task);
                    }
                }

                await Task.WhenAll(entryReadyTasks);

                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string relativeName = entry.FullName;
                    var signedPart = FindNestedPart(relativeName);

                    using (var signedStream = File.OpenRead(signedPart.Value.FileInfo.File.FullPath))
                    using (var entryStream = entry.Open())
                    {
                        log.LogMessage(MessageImportance.Low, $"Copying signed stream from {signedPart.Value.FileInfo.File.FullPath} to {ZipFileInfo.File.FullPath} -> {relativeName}.");

                        signedStream.CopyTo(entryStream);
                        entryStream.SetLength(signedStream.Length);
                    }
                }
            }
        }
        private async Task RepackWixPack(TaskLoggingHelper log, ConcurrentDictionary<FileContentKey, Task> signingTasksByContentKey, string tempDir, string wixToolsPath)
        {
            // The wixpacks can have rather long paths when fully extracted.
            // To avoid issues, use the first element of the GUID (up to first -).
            // This does leave the very remote possibility of the dir already existing. In this case, the
            // create.cmd file will always end up being extracted twice, and ExtractToDirectory
            // will fail. Because of the very very remote possibility of this happening, no
            // attempt to workaround this possibility is made.
            var workingDirGuidSegment = Guid.NewGuid().ToString().Split('-')[0];
            var outputDirGuidSegment = Guid.NewGuid().ToString().Split('-')[0];

            string workingDir = Path.Combine(tempDir, "extract", workingDirGuidSegment);
            string outputDir = Path.Combine(tempDir, "output", outputDirGuidSegment);
            string createFileName = Path.Combine(workingDir, "create.cmd");
            string outputFileName = Path.Combine(outputDir, ZipFileInfo.File.FileName);

            try
            {
                Directory.CreateDirectory(outputDir);
                ZipFile.ExtractToDirectory(ZipFileInfo.WixContentFilePath, workingDir);

                var fileList = Directory.GetFiles(workingDir, "*", SearchOption.AllDirectories);

                // Before doing this, we need to ensure that all the files we are about to repack
                // are signed.
                List<string> filesToRepack = new List<string>();
                List<Task> signingTasksToWaitOn = new List<Task>();
                foreach (var file in fileList)
                {
                    var relativeName = GetRelativeName(workingDir, file);
                    var zipPart = FindNestedPart(relativeName);
                    if (!zipPart.HasValue)
                    {
                        continue;
                    }
                    filesToRepack.Add(file);
                    if (signingTasksByContentKey.TryGetValue(zipPart.Value.FileInfo.FileContentKey, out var task))
                    {
                        signingTasksToWaitOn.Add(task);
                    }
                }

                await Task.WhenAll(signingTasksToWaitOn);

                foreach (var file in fileList)
                {
                    var relativeName = GetRelativeName(workingDir, file);
                    var signedPart = FindNestedPart(relativeName);

                    log.LogMessage(MessageImportance.Low, $"Copying signed stream from {signedPart.Value.FileInfo.File.FullPath} to {file}.");
                    File.Copy(signedPart.Value.FileInfo.File.FullPath, file, true);
                }

                if (!BatchSignUtil.RunWixTool(createFileName, outputDir, workingDir, wixToolsPath, log))
                {
                    log.LogError($"Packaging of wix file '{ZipFileInfo.File.FullPath}' failed");
                    return;
                }

                if (!File.Exists(outputFileName))
                {
                    log.LogError($"Wix tool execution passed, but output file '{outputFileName}' was not found.");
                    return;
                }

                log.LogMessage($"Created wix file {outputFileName}, replacing '{ZipFileInfo.File.FullPath}' with '{outputFileName}'");
                File.Copy(outputFileName, ZipFileInfo.File.FullPath, true);
            }
            finally
            {
                // Delete the intermediates
                Directory.Delete(workingDir, true);
                Directory.Delete(outputDir, true);
            }

            static string GetRelativeName(string workingDir, string file) => file.Substring($"{workingDir}\\".Length).Replace('\\', '/');
        }
    }
}
