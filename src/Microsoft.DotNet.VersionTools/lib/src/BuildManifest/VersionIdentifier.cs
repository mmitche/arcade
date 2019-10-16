// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.DotNet.VersionTools.Util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Microsoft.DotNet.VersionTools.BuildManifest
{
    public static class VersionIdentifier
    {
        private static readonly HashSet<string> _knownTags = new HashSet<string>
            {
                "alpha",
                "beta",
                "preview",
                "prerelease",
                "servicing",
                "rtm",
                "rc"
            };

        private static readonly char[] _delimiters = new char[] { '.', '-' };

        /// <summary>
        /// Identify the version number of an asset.
        /// 
        /// Assets can come in two forms:
        /// - Blobs that include the full path
        /// - Packages that do not include any path elements.
        /// 
        /// This method expects that a single path element (e.g. the file name or
        /// a blob directory that contains a version number)
        /// </summary>
        /// <param name="assetName">Asset Name</param>
        /// <returns>Version number, or nothing if none was found</returns>
        /// <remarks>
        /// This is particularly error prone. To constrain the problem, we apply the following assumptions
        /// which are valid for .NET Core:
        /// - We always have major.minor.patch, and it always begins the version string.
        /// - The only pre-release or build metadata labels we use begin with the _knownTags shown above.
        /// - We use additional numbers in our version numbers after the initial major.minor.patch, but any non-numeric element will end the version string
        /// - The delimiters we use in versions and file names are just . and -.
        /// </remarks>
        public static string GetVersion2(string assetName)
        {
            if (assetName.IndexOf('/') != -1)
            {
                throw new ArgumentException("Expected single path element");
            }

            // Find the start of the version number by finding the major.minor.patch.
            // Scan the string forward looking for a digit preceded
            // Begin the scan for major.minor.patch.
        }

        public static string GetVersion(string assetName)
        {
            string pathVersion = null;

            if (assetName.Contains('/'))
            {
                string[] pathSegments = assetName.Split('/');
                pathVersion = CheckIfVersionInPath(pathSegments);
                assetName = pathSegments[pathSegments.Length - 1];
            }

            string[] segments = assetName.Split('.');
            StringBuilder sb = new StringBuilder();
            int versionStart = 0;
            int versionEnd = 0;

            for (int i = 1; i < segments.Length; i++)
            {
                if (IsMajorAndMinor(segments[i - 1], segments[i]))
                {
                    versionStart = i - 1;
                    versionEnd = i;
                    i++;

                    // Once we have a major and minor we continue to check all the segments and if any have digits in it versionEnd
                    // is updated. So far, produced assets don't have an extension with digits in it, if that changes we'd need to update
                    // this logic
                    while (i < segments.Length)
                    {
                        if (IsValidSegment(segments[i]))
                        {
                            versionEnd = i;
                        }

                        i++;
                    }
                }
            }

            if (versionStart == versionEnd)
            {
                return pathVersion;
            }

            // Append major which might cointain fragments of the name so we need to only get the numeric piece out of that
            string major = GetMajor(segments[versionStart++]);
            sb.Append($"{major}.");

            while (versionStart < versionEnd)
            {
                sb.Append($"{segments[versionStart++]}.");
            }

            sb.Append($"{segments[versionEnd]}");

            string version = sb.ToString();

            if (!string.IsNullOrEmpty(pathVersion) && string.IsNullOrEmpty(version))
            {
                return null;
            }

            if (!string.IsNullOrEmpty(pathVersion) && _knownTags.Any(t => version.Contains(t)) && _knownTags.Any(k => pathVersion.Contains(k)))
            {
                return version.Length < pathVersion.Length ? version : pathVersion;
            }

            if (string.IsNullOrEmpty(pathVersion) || _knownTags.Any(t => version.Contains(t)))
            {
                return version;
            }

            return pathVersion;
        }

        private static string CheckIfVersionInPath(string[] pathSegments)
        {
            foreach (string pathSegment in pathSegments)
            {
                string version = GetVersion(pathSegment);

                if (!string.IsNullOrEmpty(version))
                {
                    return version;
                }
            }

            return null;
        }

        private static bool IsMajorAndMinor(string major, string minor)
        {
            return major.Any(char.IsDigit) && int.TryParse(minor, out int min);
        }

        private static string GetMajor(string versionSegment)
        {
            if (int.TryParse(versionSegment, out int v))
            {
                return versionSegment;
            }

            int index = versionSegment.Length - 1;
            List<char> version = new List<char>();

            while (index > 0 && char.IsDigit(versionSegment[index]))
            {
                version.Insert(0, versionSegment[index--]);
            }

            return new string(version.ToArray());
        }

        private static bool IsValidSegment(string versionSegment)
        {
            return versionSegment.Any(char.IsDigit) || _knownTags.Any(t => versionSegment.Contains(t));
        }

        /// <summary>
        /// Remove any version numbers from an asset name
        /// </summary>
        /// <param name="assetName">Asset name</param>
        /// <remarks>
        /// This method will attempt to strip away any version info from the asset id.
        /// Stripping away all the version info is not totally trivial.
        /// Multiple version numbers may exist within the blob path, and these version may not
        /// be identical. Example:
        /// - Runtime/3.0.1-servicing-19511-02/dotnet-host-3.0.1-x64.rpm
        /// 
        /// This is a bit problematic since it means that an attempt to use the version manager to determine
        /// the version will result in one of the two versions. Replacing the returned version throughout the
        /// string may result in an incorrect blob path:
        /// - Runtime/-servicing-19511-02/dotnet-host-3.0.1-x64.rpm
        /// 
        /// The good news is that there should never be more than two versions that should need to be stripped
        /// from any path: the stable version number and the non-stable (suffixed) version number. Most of the time there
        /// will be only one (a suffixed-version)
        /// 
        /// One algorithm that can work to end up with the right version is this:
        /// 1. Extract the file name from the final path.
        /// 2. Pass both the full path and the file name to the version identifier.
        /// 3. If the versions returned are both non-null, first remove the longest of the two strings from the
        ///    full path, then the shorter.
        /// 
        /// Note: This method does *not* remove any oddities introduced by removing the version elements. For instance,
        /// If removing the version element ends up introducing a "//", it will remain. It's up to the caller to interpret these
        /// appropriately and decide what to do.
        /// </remarks>
        public static string GetAssetWithoutVersions(string assetName)
        {
            string fullBlob = assetName;
            // This could be either a file name or a blob path, so use the path
            // utilities to get the file name.
            string fileElement = Path.GetFileName(fullBlob);

            List<string> versionsToRemove = new List<string>();
            string versionFromFullBlob = VersionIdentifier.GetVersion(fullBlob);

            if (!string.IsNullOrEmpty(versionFromFullBlob))
            {
                versionsToRemove.Add(versionFromFullBlob);
            }

            // If the file element is not the same as the full blob (if there were path elements)
            if (fileElement != fullBlob)
            {
                string versionFromFileElement = VersionIdentifier.GetVersion(fileElement);

                if (!string.IsNullOrEmpty(versionFromFileElement))
                {
                    versionsToRemove.Add(versionFromFileElement);
                }
            }

            // If any other types of versions appear in the future, add them to the list here.
            string fullBlobWithoutVersions = fullBlob;
            if (versionsToRemove.Count > 0)
            {
                // Things to remove!
                versionsToRemove.Sort();

                // The key here is that we remove elements that are substrings of other later *after*,
                // so iterate backwards through the list.
                for (int i = versionsToRemove.Count - 1; i >= 0; i--)
                {
                    fullBlobWithoutVersions = fullBlobWithoutVersions.Replace(versionsToRemove[i], "");
                }
            }
            
            // Now remove any double path elements, as well as any cases where 

            return fullBlobWithoutVersions;
        }
    }
}
