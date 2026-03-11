// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
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
    /// </summary>
    public sealed class PEFileAnalyzer : IFileAnalyzer
    {
        private static readonly string[] s_peExtensions = { ".dll", ".exe", ".sys", ".ocx" };

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
                return AnalyzeCore(ms, fileName);
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
                return AnalyzeCore(stream, fileName ?? string.Empty);
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        private static FileMetadata AnalyzeCore(Stream stream, string fileName)
        {
            try
            {
                // PEStreamOptions.LeaveOpen so we don't close the caller's stream.
                using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);

                if (peReader.PEHeaders?.PEHeader == null)
                {
                    return new FileMetadata(fileName);
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
                return new FileMetadata(fileName);
            }
        }
    }
}
