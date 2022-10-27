// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.DotNet.SignTool
{
    internal readonly struct ZipPart
    {
        internal string RelativeName { get; }
        internal FileWithSignInfo FileSignInfo { get; }

        internal ZipPart(string relativeName, FileWithSignInfo signInfo)
        {
            RelativeName = relativeName;
            FileSignInfo = signInfo;
        }
    }
}


