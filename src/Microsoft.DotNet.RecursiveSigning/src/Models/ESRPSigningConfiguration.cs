// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

namespace Microsoft.DotNet.RecursiveSigning.Models
{
    /// <summary>
    /// Base configuration shared by all ESRP signing providers.
    /// </summary>
    public abstract class ESRPSigningConfiguration
    {
        /// <summary>
        /// Temp directory for working files (submission JSON, output files, encrypted auth artifacts).
        /// </summary>
        public string TempDirectory { get; set; } = string.Empty;

        /// <summary>
        /// Directory where invocation logs are written.
        /// Each invocation writes stdout/stderr to a separate file.
        /// When empty, logs are only written through the ILogger pipeline.
        /// </summary>
        public string LogDirectory { get; set; } = string.Empty;

        /// <summary>
        /// When true, the provider logs submission details without invoking the signing tool.
        /// </summary>
        public bool DryRun { get; set; }

        /// <summary>
        /// When true, logs submission details and full stdout/stderr at Information level
        /// for diagnostic purposes.
        /// </summary>
        public bool VerboseLogging { get; set; }
    }
}
