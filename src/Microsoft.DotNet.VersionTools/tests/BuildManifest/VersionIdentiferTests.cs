// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.IO;
using Xunit;
using Microsoft.DotNet.VersionTools.BuildManifest;

namespace Microsoft.DotNet.VersionTools.Tests.BuildManifest
{
    public class VersionTests
    {
        [Fact]
        public void ValidateVersions()
        {
            List<VersionIdentifierTestAsset> testAssets = GetTestAssets();

            foreach (VersionIdentifierTestAsset testAsset in testAssets)
            {
                Assert.Equal(testAsset.ExpectedVersion, VersionIdentifier.GetVersion(testAsset.Name));
                Assert.Equal(testAsset.NameWithoutVersions, VersionIdentifier.GetAssetWithoutVersions(testAsset.Name));
            }
        }

        private List<VersionIdentifierTestAsset> GetTestAssets()
        {
            List<VersionIdentifierTestAsset> testAssets = new List<VersionIdentifierTestAsset>();
            string[] assets = File.ReadAllLines("BuildManifest/VersionIdentifierTestsAssets-modified.csv");

            foreach (string input in assets)
            {
                if (!string.IsNullOrEmpty(input))
                {
                    string[] values = input.Split(',');
                    string name = values[0];
                    string expectedVersion = string.IsNullOrEmpty(values[1]) ? null : values[1];
                    string nameWithoutVersions = string.IsNullOrEmpty(values[2]) ? null : values[2];
                    testAssets.Add(new VersionIdentifierTestAsset(name, expectedVersion, nameWithoutVersions));
                }
            }

            return testAssets;
        }
    }
}
