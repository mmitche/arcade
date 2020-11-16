// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.DotNet.VersionTools.BuildManifest.Model
{
    public static class SigningInformationParsingExtensions
    {
        /// <summary>
        /// Throw if there are any file extension sign information entries that conflict, meaning
        /// the same extension has different certificates
        /// </summary>
        /// <param name="fileExtensionSignInfos">File extension sign infos</param>
        /// <returns>File extension sign infos</returns>
        public static IEnumerable<FileExtensionSignInfoModel> ThrowIfConflictingFileExtensionSignInfo(
            this IEnumerable<FileExtensionSignInfoModel> fileExtensionSignInfos)
        {
            Dictionary<string, HashSet<string>> extensionToCertMapping = new Dictionary<string, HashSet<string>>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var signInfo in fileExtensionSignInfos)
            {
                if (!extensionToCertMapping.TryGetValue(signInfo.Include, out var hashSet))
                {
                    hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    extensionToCertMapping.Add(signInfo.Include, hashSet);
                }
                hashSet.Add(signInfo.CertificateName);
            }

            var conflicts = extensionToCertMapping.Where(kv => kv.Value.Count() > 0);

            if (conflicts.Count() > 0)
            {
                throw new ArgumentException(
                    $"Some extensions have conflicting FileExtensionSignInfo: {string.Join(", ", conflicts.Select(s => s.Key))}");
            }

            return fileExtensionSignInfos;
        }

        /// <summary>
        /// Throw if there are any explicit signing information entries that conflict. Explicit
        /// entries would conflict if the certificates were different and the following properties
        /// are identical:
        /// - File name
        /// - Target framework
        /// - Public key token (case insensitive)
        /// </summary>
        /// <param name="fileSignInfo">File sign info entries</param>
        /// <returns>File sign info entries</returns>
        public static IEnumerable<FileSignInfoModel> ThrowIfConflictingFileSignInfo(
            this IEnumerable<FileSignInfoModel> fileSignInfo)
        {
            // Create a simple dictionary where the key is "filename/tfm/pkt"
            Dictionary<string, HashSet<string>> keyToCertMapping = new Dictionary<string, HashSet<string>>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var signInfo in fileSignInfo)
            {
                string key = $"{signInfo.Include}/{signInfo.TargetFramework}/{signInfo.PublicKeyToken.ToLower()}";
                if (!keyToCertMapping.TryGetValue(key, out var hashSet))
                {
                    hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    keyToCertMapping.Add(key, hashSet);
                }
                hashSet.Add(signInfo.CertificateName);
            }

            var conflicts = keyToCertMapping.Where(kv => kv.Value.Count() > 0);

            if (conflicts.Count() > 0)
            {
                throw new ArgumentException(
                    $"The following files have conflicting FileSignInfo entries: {string.Join(", ", conflicts.Select(s => s.Key.Substring(0, s.Key.IndexOf("/"))))}");
            }

            return fileSignInfo;
        }

        /// <summary>
        /// Throw if there are any explicit signing information entries that are invalid. This includes:
        /// - Path elements in the file name
        /// - non-valid public key token
        /// - Empty certificate name
        /// - Invalid TFM
        /// </summary>
        /// <param name="fileSignInfo">File sign info entries</param>
        /// <returns>File sign info entries</returns>
        public static IEnumerable<FileSignInfoModel> ThrowIfInvalidFileSignInfoEntries(
            this IEnumerable<FileSignInfoModel> fileSignInfo)
        {
            return fileSignInfo;
        }

        /// <summary>
        /// Throw if there are dual sign info entries that are conflicting.
        /// If the cert names are the same, but DualSigningAllowed is different.
        /// </summary>
        /// <param name="certificateSignInfo">File sign info entries</param>
        /// <returns>File sign info entries</returns>
        public static IEnumerable<CertificatesSignInfoModel> ThrowIfConflictingCertificateSignInfo(
            this IEnumerable<CertificatesSignInfoModel> certificateSignInfo)
        {
            Dictionary<string, HashSet<bool>> extensionToCertMapping = new Dictionary<string, HashSet<bool>>();
            foreach (var signInfo in certificateSignInfo)
            {
                if (!extensionToCertMapping.TryGetValue(signInfo.Include, out var hashSet))
                {
                    hashSet = new HashSet<bool>();
                    extensionToCertMapping.Add(signInfo.Include, hashSet);
                }
                hashSet.Add(signInfo.DualSigningAllowed);
            }

            var conflicts = extensionToCertMapping.Where(kv => kv.Value.Count() > 0);

            if (conflicts.Count() > 0)
            {
                throw new ArgumentException(
                    $"Some certificates have conflicting DualSigningAllowed entries: {string.Join(", ", conflicts.Select(s => s.Key))}");
            }

            return certificateSignInfo;
        }

        /// <summary>
        /// Throw if there conflicting strong name entries. A strong name entry uses the public key token
        /// as the key, mapping to a strong name and a cert.
        /// </summary>
        /// <param name="strongNameSignInfo">File sign info entries</param>
        /// <returns>File sign info entries</returns>
        public static IEnumerable<StrongNameSignInfoModel> ThrowIfConflictingStrongNameSignInfo(
            this IEnumerable<StrongNameSignInfoModel> strongNameSignInfo)
        {
            Dictionary<string, HashSet<string>> pktMapping = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var signInfo in strongNameSignInfo)
            {
                string value = $"{signInfo.Include}/{signInfo.CertificateName}";
                if (!pktMapping.TryGetValue(signInfo.PublicKeyToken, out var hashSet))
                {
                    hashSet = new HashSet<string>();
                    pktMapping.Add(value, hashSet);
                }
                hashSet.Add(value);
            }

            var conflicts = pktMapping.Where(kv => kv.Value.Count() > 0);

            if (conflicts.Count() > 0)
            {
                throw new ArgumentException(
                    $"Some public key tokens have conflicting StrongNameSignInfo entries: {string.Join(", ", conflicts.Select(s => s.Key))}");
            }

            return strongNameSignInfo;
        }
    }
}
