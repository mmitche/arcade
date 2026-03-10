// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.DotNet.RecursiveSigning.Abstractions;
using Microsoft.DotNet.RecursiveSigning.Models;

namespace Microsoft.DotNet.RecursiveSigning.Implementation
{
    /// <summary>
    /// Abstract base class for ESRP signing providers. Provides the shared
    /// <see cref="SignFilesAsync"/> template (null-check → group → dry-run → execute),
    /// certificate grouping, operations extraction, and common logging helpers.
    /// </summary>
    public abstract class ESRPSigningProviderBase : ISigningProvider
    {
        protected readonly IProcessRunner ProcessRunner;
        protected readonly ILogger Logger;

        protected static readonly JsonSerializerOptions PrettyJsonOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        protected static readonly JsonSerializerOptions CompactJsonOptions = new();

        protected ESRPSigningProviderBase(IProcessRunner processRunner, ILogger logger)
        {
            ProcessRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>The provider-specific configuration (exposes shared DryRun / VerboseLogging / dirs).</summary>
        protected abstract ESRPSigningConfiguration Configuration { get; }

        /// <summary>Human-readable name used in log messages (e.g. "ESRP CLI", "ESRPClient.exe").</summary>
        protected abstract string ProviderName { get; }

        // ────────────────────────────────────────────────────────────────────────
        //  Template method – implements ISigningProvider
        // ────────────────────────────────────────────────────────────────────────

        public async Task<bool> SignFilesAsync(
            IReadOnlyList<(FileNode node, string outputPath)> files,
            CancellationToken cancellationToken = default)
        {
            if (files == null || files.Count == 0)
            {
                return true;
            }

            var groups = GroupFilesByCertificate(files);

            if (Configuration.DryRun)
            {
                LogDryRun(groups);
                return true;
            }

            Logger.LogInformation("Signing {Count} file(s) across {Groups} certificate group(s) via {Provider}",
                files.Count, groups.Count, ProviderName);

            return await ExecuteSigningAsync(groups, files, cancellationToken);
        }

        /// <summary>Perform the actual signing after grouping and dry-run checks.</summary>
        protected abstract Task<bool> ExecuteSigningAsync(
            Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)> groups,
            IReadOnlyList<(FileNode node, string outputPath)> allFiles,
            CancellationToken cancellationToken);

        /// <summary>Log the dry-run details (provider-specific formatting).</summary>
        protected abstract void LogDryRun(
            Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)> groups);

        // ────────────────────────────────────────────────────────────────────────
        //  Certificate grouping & operations
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Groups files by their certificate identifier's friendly name.
        /// </summary>
        internal static Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)>
            GroupFilesByCertificate(IReadOnlyList<(FileNode node, string outputPath)> files)
        {
            var groups = new Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var entry in files)
            {
                var certId = entry.node.CertificateIdentifier as ESRPCertificateIdentifier
                    ?? throw new InvalidOperationException(
                        $"File '{entry.node.Location.FilePathOnDisk}' does not have an ESRPCertificateIdentifier.");

                if (!groups.TryGetValue(certId.FriendlyName, out var group))
                {
                    group = (certId, new List<(FileNode, string)>());
                    groups[certId.FriendlyName] = group;
                }

                group.files.Add(entry);
            }

            return groups;
        }

        /// <summary>
        /// Extracts the operations array from a CertificateDefinition.
        /// Accepts either a bare JSON array or an object with an <c>operations</c> property.
        /// </summary>
        internal static JsonElement ExtractOperations(JsonElement certificateDefinition)
        {
            if (certificateDefinition.ValueKind == JsonValueKind.Array)
            {
                return certificateDefinition;
            }

            if (certificateDefinition.ValueKind == JsonValueKind.Object &&
                certificateDefinition.TryGetProperty("operations", out var ops))
            {
                return ops;
            }

            throw new InvalidOperationException(
                "CertificateDefinition must be either an operations array or an object with an 'operations' property.");
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Logging helpers
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Logs at Information level when verbose logging is enabled, Debug otherwise.
        /// </summary>
        protected void LogVerbose(string message, params object[] args)
        {
            if (Configuration.VerboseLogging)
            {
                Logger.LogInformation(message, args);
            }
            else
            {
                Logger.LogDebug(message, args);
            }
        }

        /// <summary>
        /// Writes stdout, stderr, and redacted arguments for one signing tool invocation
        /// to a log file. Files are always written (even in non-verbose mode) so that
        /// build operators can inspect signing details after the fact.
        /// </summary>
        protected void WriteInvocationLog(
            string logLabel, string logFilePrefix, ProcessResult result, string redactedArguments)
        {
            var logDir = Configuration.LogDirectory;
            if (string.IsNullOrWhiteSpace(logDir))
            {
                return;
            }

            try
            {
                Directory.CreateDirectory(logDir);
                var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
                var logFile = Path.Combine(logDir, $"{logFilePrefix}-{timestamp}.log");

                var sb = new StringBuilder();
                sb.AppendLine($"=== {logLabel} ===");
                sb.AppendLine($"Timestamp (UTC): {DateTime.UtcNow:O}");
                sb.AppendLine($"Exit code: {result.ExitCode}");
                sb.AppendLine($"Arguments (redacted): {redactedArguments}");
                sb.AppendLine();
                sb.AppendLine("=== stdout ===");
                sb.AppendLine(result.StandardOutput);
                if (!string.IsNullOrWhiteSpace(result.StandardError))
                {
                    sb.AppendLine("=== stderr ===");
                    sb.AppendLine(result.StandardError);
                }

                File.WriteAllText(logFile, sb.ToString());
                Logger.LogInformation("{Provider} log written to: {LogFile}", ProviderName, logFile);
            }
            catch (Exception ex)
            {
                Logger.LogWarning("Failed to write {Provider} invocation log for {Label}: {Error}",
                    ProviderName, logLabel, ex.Message);
            }
        }

        protected void TryDeleteDirectory(string path)
        {
            try { Directory.Delete(path, true); }
            catch (Exception ex)
            {
                Logger.LogWarning("Failed to delete working directory {Path}: {Error}", path, ex.Message);
            }
        }
    }
}
