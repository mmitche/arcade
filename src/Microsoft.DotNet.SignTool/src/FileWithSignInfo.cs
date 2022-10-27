// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;

namespace Microsoft.DotNet.SignTool
{
    internal readonly struct FileWithSignInfo
    {
        internal string FileName => FileInfo.File.FileName;
        internal string FullPath => FileInfo.File.FullPath;
        internal readonly SignInfo SignInfo;
        internal readonly FileInfo FileInfo;

        // optional file information that allows to disambiguate among multiple files with the same name:
        internal readonly string TargetFramework;

        internal bool HasSignableParts { get; }

        internal bool ShouldRepack => HasSignableParts;

        internal bool ShouldTrack => SignInfo.ShouldSign || ShouldRepack;

        internal FileWithSignInfo(FileInfo fileInfo, SignInfo signInfo, string targetFramework = null, bool hasSignableParts = false)
        {
            Debug.Assert(fileInfo.File.FullPath != null);
            Debug.Assert(!fileInfo.File.ContentHash.IsDefault && fileInfo.File.ContentHash.Length == 256 / 8);
            Debug.Assert(targetFramework != "");

            FileInfo = fileInfo;
            SignInfo = signInfo;
            TargetFramework = targetFramework;
            HasSignableParts = hasSignableParts;
        }

        public override string ToString()
            => $"File '{FileName}'" +
               (TargetFramework != null ? $" TargetFramework='{TargetFramework}'" : "") +
               $" Certificate='{SignInfo.Certificate}'" +
               (SignInfo.StrongName != null ? $" StrongName='{SignInfo.StrongName}'" : "");

        internal FileWithSignInfo WithSignableParts()
            => new FileWithSignInfo(FileInfo, SignInfo.WithIsAlreadySigned(false), TargetFramework, true);
    }
}
