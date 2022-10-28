// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.IO.Packaging;

namespace Microsoft.DotNet.SignTool
{
    /// <summary>
    /// Data for a zip container. Can refer to any zip format such as VSIX, NuPkg, or a raw zip archive.
    /// </summary>
    internal sealed class ZipData
    {
        /// <summary>
        /// Signing information.
        /// </summary>
        internal FileInfo FileInfo { get; }

        /// <summary>
        /// The parts inside this container which may need to be signed.
        /// </summary>
        internal ImmutableDictionary<string, ZipPart> NestedParts { get; }

        internal ZipData(FileInfo fileInfo, ImmutableDictionary<string, ZipPart> nestedBinaryParts)
        {
            FileInfo = fileInfo;
            NestedParts = nestedBinaryParts;
        }

        internal ZipPart? FindNestedPart(string relativeName)
        {
            if (NestedParts.TryGetValue(relativeName, out ZipPart part))
            {
                return part;
            }

            return null;
        }

        /// <summary>
        /// Repack the zip container with the signed files.
        /// </summary>
        public void Repack(TaskLoggingHelper log, string tempDir = null, string wixToolsPath = null)
        {
#if NET472
            if (FileInfo.FileInfo.IsVsix())
            {
                RepackPackage(log);
            }
            else
#endif
            {
                if (FileInfo.FileInfo.IsWixContainer())
                {
                    RepackWixPack(log, tempDir, wixToolsPath);
                }
                else 
                {
                    RepackRawZip(log);
                }
            }
        }

#if NET472
        /// <summary>
        /// Repack a zip container with a package structure.
        /// </summary>
        private void RepackPackage(TaskLoggingHelper log)
        {
            string getPartRelativeFileName(PackagePart part)
            {
                var path = part.Uri.OriginalString;
                if (!string.IsNullOrEmpty(path) && path[0] == '/')
                {
                    path = path.Substring(1);
                }

                return path;
            }
            
            using (var package = Package.Open(FileInfo.FullPath, FileMode.Open, FileAccess.ReadWrite))
            {
                foreach (var part in package.GetParts())
                {
                    var relativeName = getPartRelativeFileName(part);
                    var signedPart = FindNestedPart(relativeName);
                    if (!signedPart.HasValue)
                    {
                        log.LogMessage(MessageImportance.Low, $"Didn't find signed part for nested file: {FileInfo.FullPath} -> {relativeName}");
                        continue;
                    }

                    using (var signedStream = File.OpenRead(signedPart.Value.FileInfo.FullPath))
                    using (var partStream = part.GetStream(FileMode.Open, FileAccess.ReadWrite))
                    {
                        log.LogMessage(MessageImportance.Low, $"Copying signed stream from {signedPart.Value.FileInfo.FullPath} to {FileInfo.FullPath} -> {relativeName}.");

                        signedStream.CopyTo(partStream);
                        partStream.SetLength(signedStream.Length);
                    }
                }
            }
        }
#endif
        /// <summary>
        /// Repack raw zip container.
        /// </summary>
        private void RepackRawZip(TaskLoggingHelper log)
        {
            using (var archive = new ZipArchive(File.Open(FileInfo.FullPath, FileMode.Open), ZipArchiveMode.Update))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string relativeName = entry.FullName;
                    var signedPart = FindNestedPart(relativeName);
                    if (!signedPart.HasValue)
                    {
                        log.LogMessage(MessageImportance.Low, $"Didn't find signed part for nested file: {FileInfo.FullPath} -> {relativeName}");
                        continue;
                    }

                    using (var signedStream = File.OpenRead(signedPart.Value.FileInfo.FullPath))
                    using (var entryStream = entry.Open())
                    {
                        log.LogMessage(MessageImportance.Low, $"Copying signed stream from {signedPart.Value.FileInfo.FullPath} to {FileInfo.FullPath} -> {relativeName}.");

                        signedStream.CopyTo(entryStream);
                        entryStream.SetLength(signedStream.Length);
                    }
                }
            }
        }
        private void RepackWixPack(TaskLoggingHelper log, string tempDir, string wixToolsPath)
        {
            // The wixpacks can have rather long paths when fully extracted.
            // To avoid issues, use the first element of the GUID (up to first -).
            // This does leave the very remote possibility of the dir already existing. In this case, the
            // create.cmd file will always end up being extracted twice, and ExtractToDirectory
            // will fail. Because of the very very remote possibility of this happening, no
            // attempt to workaround this possibility is made.
            var workingDirGuidSegment = Guid.NewGuid().ToString().Split('-')[0];
            var outputDirGuidSegment = Guid.NewGuid().ToString().Split('-')[0];

            string workingDir = Path.Combine(tempDir, "extract", workingDirGuidSegment);
            string outputDir = Path.Combine(tempDir, "output", outputDirGuidSegment);
            string createFileName = Path.Combine(workingDir, "create.cmd");
            string outputFileName = Path.Combine(outputDir, FileInfo.FileName);

            try
            {
                Directory.CreateDirectory(outputDir);
                ZipFile.ExtractToDirectory(FileInfo.FileInfo.WixContentFilePath, workingDir);

                var fileList = Directory.GetFiles(workingDir, "*", SearchOption.AllDirectories);
                foreach (var file in fileList)
                {
                    var relativeName = file.Substring($"{workingDir}\\".Length).Replace('\\', '/');
                    var signedPart = FindNestedPart(relativeName);
                    if (!signedPart.HasValue)
                    {
                        log.LogMessage(MessageImportance.Low, $"Didn't find signed part for nested file: {FileInfo.FullPath} -> {relativeName}");
                        continue;
                    }
                    log.LogMessage(MessageImportance.Low, $"Copying signed stream from {signedPart.Value.FileInfo.FullPath} to {file}.");
                    File.Copy(signedPart.Value.FileInfo.FullPath, file, true);
                }

                if (!BatchSignUtil.RunWixTool(createFileName, outputDir, workingDir, wixToolsPath, log))
                {
                    log.LogError($"Packaging of wix file '{FileInfo.FullPath}' failed");
                    return;
                }

                if (!File.Exists(outputFileName))
                {
                    log.LogError($"Wix tool execution passed, but output file '{outputFileName}' was not found.");
                    return;
                }

                log.LogMessage($"Created wix file {outputFileName}, replacing '{FileInfo.FullPath}' with '{outputFileName}'");
                File.Copy(outputFileName, FileInfo.FullPath, true);
            }
            finally
            {
                // Delete the intermediates
                Directory.Delete(workingDir, true);
                Directory.Delete(outputDir, true);
            }
        }
    }
}
