// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;

namespace Microsoft.DotNet.RecursiveSigning.Models
{
    /// <summary>
    /// Request to the signing orchestrator.
    /// </summary>
    public sealed class SigningRequest
    {
        /// <summary>
        /// Input files to sign (top-level artifacts).
        /// </summary>
        public IReadOnlyList<FileInfo> InputFiles { get; }

        /// <summary>
        /// Temporary directory for unpacking containers and other intermediate files.
        /// </summary>
        public string TempDirectory { get; }

        /// <summary>
        /// Optional output directory for root input artifacts.
        /// When set, final signed root files are copied here while working files continue to be updated in place.
        /// </summary>
        public string? OutputDirectory { get; }

        /// <summary>
        /// Options for signing process.
        /// </summary>
        public SigningOptions Options { get; }

        public SigningRequest(
            IReadOnlyList<FileInfo> inputFiles,
            string tempDirectory,
            SigningOptions options,
            string? outputDirectory = null)
        {
            InputFiles = inputFiles ?? throw new ArgumentNullException(nameof(inputFiles));
            TempDirectory = tempDirectory ?? throw new ArgumentNullException(nameof(tempDirectory));
            Options = options ?? throw new ArgumentNullException(nameof(options));
            OutputDirectory = string.IsNullOrWhiteSpace(outputDirectory) ? null : outputDirectory;
        }
    }
}
