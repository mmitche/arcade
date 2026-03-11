// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DotNet.RecursiveSigning.Abstractions;
using Microsoft.DotNet.RecursiveSigning.Models;

namespace Microsoft.DotNet.RecursiveSigning.Implementation
{
    /// <summary>
    /// Analyzes PE (Portable Executable) files — .dll, .exe, .sys, etc.
    /// Detects Authenticode signatures by inspecting the PE header's
    /// CertificateTableDirectory entry, matching the approach from SignTool.
    /// Validates that the COFF Machine type is one that AuthentiCode signing
    /// tools can process — .NET crossgen2 produces R2R assemblies with
    /// non-standard Machine types (e.g. 0xFD1D for linux-x64) that SignTool
    /// rejects with ERROR_BAD_EXE_FORMAT.
    /// </summary>
    public sealed class PEFileAnalyzer : IFileAnalyzer
    {
        private static readonly string[] s_peExtensions = { ".dll", ".exe", ".sys", ".ocx" };

        /// <summary>
        /// PE Machine types that AuthentiCode signing tools (SignTool) can process.
        /// </summary>
        private static readonly HashSet<ushort> s_signableMachineTypes =
        [
            0x014C, // IMAGE_FILE_MACHINE_I386 (x86, also AnyCPU IL-only)
            0x01C4, // IMAGE_FILE_MACHINE_ARMNT (ARM Thumb-2)
            0x8664, // IMAGE_FILE_MACHINE_AMD64 (x64)
            0xAA64, // IMAGE_FILE_MACHINE_ARM64
        ];

        public bool CanAnalyze(string fileName)
        {
            var ext = Path.GetExtension(fileName);
            return s_peExtensions.Any(pe => ext.Equals(pe, StringComparison.OrdinalIgnoreCase));
        }

        public async Task<IFileMetadata> AnalyzeAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new ArgumentException("File path cannot be null or whitespace.", nameof(filePath));
            }

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            return await AnalyzeAsync(stream, Path.GetFileName(filePath), cancellationToken);
        }

        public async Task<IFileMetadata> AnalyzeAsync(
            Stream contentStream, string fileName, CancellationToken cancellationToken = default)
        {
            if (contentStream == null)
            {
                throw new ArgumentNullException(nameof(contentStream));
            }

            if (string.IsNullOrWhiteSpace(fileName))
            {
                throw new ArgumentException("File name cannot be null or whitespace.", nameof(fileName));
            }

            if (!contentStream.CanSeek)
            {
                // PEReader needs a seekable stream; copy asynchronously.
                using var ms = new MemoryStream();
                await contentStream.CopyToAsync(ms, cancellationToken);
                ms.Position = 0;
                return AnalyzePE(ms, fileName);
            }

            return Analyze(contentStream, fileName);
        }

        /// <summary>
        /// Synchronously analyzes a seekable PE stream. Separated for testability and
        /// because <see cref="PEReader"/> is not async.
        /// </summary>
        internal static IFileMetadata Analyze(Stream stream, string? fileName = null)
        {
            var originalPosition = stream.Position;
            try
            {
                stream.Position = 0;
                return AnalyzePE(stream, fileName ?? string.Empty);
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        private static FileMetadata AnalyzePE(Stream stream, string fileName)
        {
            try
            {
                // PEStreamOptions.LeaveOpen so we don't close the caller's stream.
                using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);

                if (peReader.PEHeaders?.PEHeader == null)
                {
                    return new FileMetadata(fileName, canBeSigned: false);
                }

                // Validate the COFF Machine type is one that signing tools support.
                ushort machine = (ushort)peReader.PEHeaders.CoffHeader.Machine;
                if (!s_signableMachineTypes.Contains(machine))
                {
                    return new FileMetadata(
                        fileName: fileName,
                        executableType: ExecutableType.PE,
                        canBeSigned: false);
                }

                // Authenticode signature check: the CertificateTableDirectory in the
                // PE header's data directory points to the Authenticode signature.
                // If Size > 0, the file has been signed.
                var certDir = peReader.PEHeaders.PEHeader.CertificateTableDirectory;
                bool isSigned = certDir.Size > 0;

                return new FileMetadata(
                    fileName: fileName,
                    executableType: ExecutableType.PE,
                    isAlreadySigned: isSigned);
            }
            catch (BadImageFormatException)
            {
                // Not a valid PE file despite having a PE extension.
                // This also handles zero-length streams.
                return new FileMetadata(fileName, canBeSigned: false);
            }
        }
    }
}
