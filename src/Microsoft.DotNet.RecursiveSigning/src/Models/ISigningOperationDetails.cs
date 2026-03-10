// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System.Collections.Generic;

namespace Microsoft.DotNet.RecursiveSigning.Models
{
    /// <summary>
    /// Provider-specific details about a signing operation, attached to a
    /// <see cref="FileNodeBase"/> after the signing provider processes it.
    /// </summary>
    public interface ISigningOperationDetails
    {
        /// <summary>
        /// Human-readable name of the signing provider (e.g. "ESRP CLI", "ESRPClient.exe", "Dry Run").
        /// </summary>
        string ProviderName { get; }

        /// <summary>
        /// Returns provider-specific key/value pairs for serialization into a signing report.
        /// </summary>
        IDictionary<string, object?> GetDetails();
    }
}
