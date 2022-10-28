// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.DotNet.SignTool
{
    internal readonly struct ZipPart
    {
        internal string RelativeName { get; }
        internal FileInfo FileInfo { get; }

        internal ZipPart(string relativeName, FileInfo fileInfo)
        {
            RelativeName = relativeName;
            FileInfo = fileInfo;
        }
    }
}


