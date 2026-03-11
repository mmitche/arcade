// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.DotNet.RecursiveSigning.Models
{
    /// <summary>
    /// Options for the signing process.
    /// </summary>
    public sealed class SigningOptions
    {
        /// <summary>
        /// Maximum degree of parallelism for container repack operations.
        /// </summary>
        public int MaxRepackParallelism { get; }

        public SigningOptions(int maxRepackParallelism = 4)
        {
            MaxRepackParallelism = maxRepackParallelism;
        }
    }
}
