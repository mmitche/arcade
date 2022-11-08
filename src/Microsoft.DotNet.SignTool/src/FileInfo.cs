// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System;
using System.Reflection;
using NuGet.Packaging.Signing;

namespace Microsoft.DotNet.SignTool
{
    public class FileInfo
    {
        public FileInfo(PathWithHash file, PathWithHash parentContainer, string collisionPriorityId, string wixContentFilePath)
        {
            File = file;
            ParentContainer = parentContainer;
            CollisionPriorityId = collisionPriorityId;
            WixContentFilePath = wixContentFilePath;
            FileContentKey = new FileContentKey(file.ContentHash, file.FileName);
        }

        public readonly PathWithHash File;
        public readonly PathWithHash ParentContainer;
        internal readonly FileContentKey FileContentKey;
        internal readonly string WixContentFilePath;
        public readonly string CollisionPriorityId;

        internal static bool IsSignableFile(string path) =>
            SignToolConstants.SignableExtensions.Contains(Path.GetExtension(path)) ||
            SignToolConstants.SignableOSXExtensions.Contains(Path.GetExtension(path));

        internal static bool IsPEFile(string path)
            => Path.GetExtension(path) == ".exe" || Path.GetExtension(path) == ".dll";

        internal static bool IsVsix(string path)
            => Path.GetExtension(path).Equals(".vsix", StringComparison.OrdinalIgnoreCase);

        internal static bool IsMPack(string path)
            => Path.GetExtension(path).Equals(".mpack", StringComparison.OrdinalIgnoreCase);

        internal static bool IsNupkg(string path)
            => Path.GetExtension(path).Equals(".nupkg", StringComparison.OrdinalIgnoreCase);

        internal static bool IsSymbolsNupkg(string path)
            => path.EndsWith(".symbols.nupkg", StringComparison.OrdinalIgnoreCase);

        internal static bool IsZip(string path)
            => Path.GetExtension(path).Equals(".zip", StringComparison.OrdinalIgnoreCase);

        internal static bool IsWix(string path)
            => (Path.GetExtension(path).Equals(".msi", StringComparison.OrdinalIgnoreCase)
                || Path.GetExtension(path).Equals(".wixlib", StringComparison.OrdinalIgnoreCase));

        internal static bool IsPowerShellScript(string path)
            => Path.GetExtension(path).Equals(".ps1", StringComparison.OrdinalIgnoreCase)
            || Path.GetExtension(path).Equals(".psd1", StringComparison.OrdinalIgnoreCase)
            || Path.GetExtension(path).Equals(".psm1", StringComparison.OrdinalIgnoreCase);

        internal static bool IsPackage(string path)
            => IsVsix(path) || IsNupkg(path);

        internal static bool IsZipContainer(string path)
            => IsPackage(path) || IsMPack(path) || IsZip(path);

        internal bool IsPEFile() => IsPEFile(File.FileName);

        internal bool IsManaged() => ContentUtil.IsManaged(File.FullPath);

        internal bool IsCrossgened() => ContentUtil.IsCrossgened(File.FullPath);

        internal bool IsVsix() => IsVsix(File.FileName);

        internal bool IsNupkg() => IsNupkg(File.FileName) && !IsSymbolsNupkg();

        internal bool IsSymbolsNupkg() => IsSymbolsNupkg(File.FileName);

        internal bool IsZip() => IsZip(File.FileName);

        internal bool IsZipContainer() => IsZipContainer(File.FileName);

        internal bool IsWix() => IsWix(File.FileName);

        // A wix file is an Container if it has the proper extension AND the content
        // (ie *.wixpack.zip) is available, otherwise it's treated like a normal file
        internal bool IsWixContainer() =>
            WixContentFilePath != null
            && (IsWix(File.FileName)
                || Path.GetExtension(File.FileName).Equals(".exe", StringComparison.OrdinalIgnoreCase));

        internal bool IsExecutableWixContainer() =>
            IsWixContainer() &&
            (Path.GetExtension(File.FileName).Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
             Path.GetExtension(File.FileName).Equals(".msi", StringComparison.OrdinalIgnoreCase));

        internal bool IsContainer() => IsZipContainer() || IsWixContainer();

        internal bool IsPackage() => IsPackage(File.FileName);

        internal bool IsPowerShellScript() => IsPowerShellScript(File.FileName);
    }
}
