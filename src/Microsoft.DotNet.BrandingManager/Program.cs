// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using CommandLine;

namespace Microsoft.DotNet.BrandingManager
{
    class Program
    {
        static int Main(string[] args)
        {
            return Parser.Default.ParseArguments(args, typeof(CheckCommandLineOptions), typeof(UpdateCommandLineOptions))
                .MapResult((CheckCommandLineOptions opts) => CheckBranding(opts),
                           (UpdateCommandLineOptions opts) => UpdateBranding(opts),
                           (errs => 1));
        }

        private static int CheckBranding(CheckCommandLineOptions options)
        {
            return 1;
        }

        private static int UpdateBranding(UpdateCommandLineOptions options)
        {
            return 1;
        }
    }
}
