// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using CommandLine;

namespace Microsoft.DotNet.BrandingManager
{
    [Verb("update", HelpText = "Updates the branding in various branches and repos")]
    class UpdateCommandLineOptions
    {
        [Option("input", Required = true, HelpText = "Input file in json file containing the branding update definition.")]
        public string Input { get; set; }

        [Option("pat", Required = true, HelpText = "GitHub PAT for accessing repos.")]
        public string GitHubPat { get; set; }
    }
}
