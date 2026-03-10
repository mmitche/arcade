// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

namespace Microsoft.DotNet.RecursiveSigning.Models
{
    /// <summary>
    /// Configuration for the ESRPClient.exe signing provider.
    /// </summary>
    public sealed class ESRPClientExeSigningConfiguration : ESRPSigningConfiguration
    {
        /// <summary>
        /// Path to EsrpClient.exe.
        /// </summary>
        public string ESRPClientExePath { get; set; } = string.Empty;

        /// <summary>
        /// ESRP client identifier (passed in auth JSON as <c>EsrpClientId</c>).
        /// Optional when <c>ESRP_AUTH_CONFIG</c> environment variable is set.
        /// </summary>
        public string? EsrpClientId { get; set; }

        /// <summary>
        /// AAD app registration client ID (passed in auth JSON as <c>ClientId</c>).
        /// Optional when <c>ESRP_AUTH_CONFIG</c> environment variable is set.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// AAD tenant ID.
        /// Optional when <c>ESRP_AUTH_CONFIG</c> environment variable is set.
        /// </summary>
        public string? TenantId { get; set; }

        /// <summary>
        /// Submission timeout in minutes. Converted to seconds for the config JSON
        /// <c>EsrpSessionTimeoutInSec</c> field.
        /// </summary>
        public int TimeoutInMinutes { get; set; } = 30;

        /// <summary>
        /// Max degree of parallelism for ESRP session.
        /// </summary>
        public int MaxDegreeOfParallelism { get; set; } = 4;

    }
}
