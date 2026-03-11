// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using Microsoft.DotNet.RecursiveSigning.Abstractions;

namespace Microsoft.DotNet.RecursiveSigning.Models
{
    /// <summary>
    /// Result from the signing orchestrator.
    /// </summary>
    public sealed class SigningResult
    {
        /// <summary>
        /// Whether signing completed successfully.
        /// </summary>
        public bool Success { get; }

        /// <summary>
        /// Errors that occurred during signing.
        /// </summary>
        public IReadOnlyList<SigningError> Errors { get; }

        /// <summary>
        /// Tracks each root input file with its output location and whether it was updated.
        /// </summary>
        public IReadOnlyList<FileResult> FileResults { get; }

        /// <summary>
        /// Telemetry about the signing process.
        /// </summary>
        public SigningTelemetry Telemetry { get; }

        /// <summary>
        /// The signing dependency graph from the completed operation.
        /// Available for post-signing inspection, serialization, and diagnostics.
        /// </summary>
        public ISigningGraph? Graph { get; }

        public SigningResult(
            bool success,
            IReadOnlyList<SigningError> errors,
            SigningTelemetry telemetry,
            IReadOnlyList<FileResult>? fileResults = null,
            ISigningGraph? graph = null)
        {
            Success = success;
            Errors = errors ?? throw new ArgumentNullException(nameof(errors));
            Telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
            FileResults = fileResults ?? Array.Empty<FileResult>();
            Graph = graph;
        }
    }

    /// <summary>
    /// Tracks the input-to-output mapping and update status for a single root input file.
    /// </summary>
    public sealed class FileResult
    {
        /// <summary>
        /// Original input file path as provided to the signing request.
        /// </summary>
        public string InputPath { get; }

        /// <summary>
        /// Output file path (same as input when no output directory is configured,
        /// otherwise the relocated path under the output directory).
        /// </summary>
        public string OutputPath { get; }

        /// <summary>
        /// Whether the file was modified during signing (signed, repacked, or had its content updated).
        /// </summary>
        public bool WasUpdated { get; }

        public FileResult(string inputPath, string outputPath, bool wasUpdated)
        {
            InputPath = inputPath ?? throw new ArgumentNullException(nameof(inputPath));
            OutputPath = outputPath ?? throw new ArgumentNullException(nameof(outputPath));
            WasUpdated = wasUpdated;
        }
    }

    /// <summary>
    /// Telemetry data from signing.
    /// </summary>
    public sealed class SigningTelemetry
    {
        public int TotalFiles { get; set; }
        public int UniqueFilesSigned { get; set; }
        public int FilesSkipped { get; set; }
        public int DuplicateFiles { get; set; }
        public int SigningRounds { get; set; }
        public TimeSpan Duration { get; set; }
        public TimeSpan DiscoveryDuration { get; set; }
        public TimeSpan SigningDuration { get; set; }
        public TimeSpan FinalizationDuration { get; set; }

        /// <summary>
        /// Per-round timing: each entry is (signingTime, repackTime, filesInRound).
        /// </summary>
        public IReadOnlyList<SigningRoundTelemetry> Rounds { get; set; } = Array.Empty<SigningRoundTelemetry>();
    }

    /// <summary>
    /// Telemetry for a single signing round.
    /// </summary>
    public sealed class SigningRoundTelemetry
    {
        public int RoundNumber { get; set; }
        public int FilesSigned { get; set; }
        public TimeSpan SigningDuration { get; set; }
        public TimeSpan RepackDuration { get; set; }
    }
}
