// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using Microsoft.DotNet.RecursiveSigning.Models;

namespace Microsoft.DotNet.RecursiveSigning.Implementation
{
    /// <summary>
    /// Signing details produced by the ESRP CLI provider.
    /// </summary>
    public sealed class ESRPCliSigningDetails : ISigningOperationDetails
    {
        public string ProviderName => "ESRP CLI";

        /// <summary>
        /// ESRP operation ID returned by the ESRP service, if available.
        /// </summary>
        public Guid? OperationId { get; }

        /// <summary>
        /// Certificate group name that this file was signed under.
        /// </summary>
        public string CertificateGroup { get; }

        public ESRPCliSigningDetails(string certificateGroup, Guid? operationId = null)
        {
            CertificateGroup = certificateGroup ?? throw new ArgumentNullException(nameof(certificateGroup));
            OperationId = operationId;
        }

        public IDictionary<string, object?> GetDetails()
        {
            var details = new Dictionary<string, object?>
            {
                ["certificateGroup"] = CertificateGroup,
            };

            if (OperationId.HasValue)
            {
                details["operationId"] = OperationId.Value.ToString();
            }

            return details;
        }
    }

    /// <summary>
    /// Signing details produced by the ESRPClient.exe provider.
    /// </summary>
    public sealed class ESRPClientExeSigningDetails : ISigningOperationDetails
    {
        public string ProviderName => "ESRPClient.exe";

        /// <summary>
        /// Certificate group name that this file was signed under.
        /// </summary>
        public string CertificateGroup { get; }

        public ESRPClientExeSigningDetails(string certificateGroup)
        {
            CertificateGroup = certificateGroup ?? throw new ArgumentNullException(nameof(certificateGroup));
        }

        public IDictionary<string, object?> GetDetails()
        {
            return new Dictionary<string, object?>
            {
                ["certificateGroup"] = CertificateGroup,
            };
        }
    }

    /// <summary>
    /// Signing details produced by the dry-run provider.
    /// </summary>
    public sealed class DryRunSigningDetails : ISigningOperationDetails
    {
        public string ProviderName => "Dry Run";

        public IDictionary<string, object?> GetDetails()
        {
            return new Dictionary<string, object?>
            {
                ["dryRun"] = true,
            };
        }
    }
}
