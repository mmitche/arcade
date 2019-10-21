// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.IO;
using Xunit;
using Microsoft.DotNet.VersionTools.BuildManifest;
using NuGet.ContentModel;

namespace Microsoft.DotNet.VersionTools.Tests.BuildManifest
{
    public class VersionTests
    {
        // Simple set of versions from inline data to call out simple failure cases.
        [Theory]
        [InlineData("1.0.0", "1.0.0")]
        [InlineData("10.0.1", "10.0.1")]
        [InlineData("10.0.1-", "10.0.1")]
        [InlineData("10.0.1-beta.final", "10.0.1-beta.final")]
        [InlineData("10.0.1-preview1.12345.1", "10.0.1-preview1.12345.1")]
        [InlineData("FooPackage.1.0.0", "1.0.0")]
        [InlineData("FooPackage.10.0.1", "10.0.1")]
        [InlineData("FooPackage.10.0.1-beta.final", "10.0.1-beta.final")]
        [InlineData("FooPackage.10.0.1-preview1.12345.1", "10.0.1-preview1.12345.1")]
        [InlineData("What.FooPackage.1.0.0", "1.0.0")]
        [InlineData("What.2.2.FooPackage.10.0.1", "10.0.1")]
        [InlineData("What.FooPackage.10.0.1-beta.final", "10.0.1-beta.final")]
        [InlineData("What.1.FooPackage.10.0.1-preview1.12345.1", "10.0.1-preview1.12345.1")]
        [InlineData("What-Is-A.FooPackage.1.0.0", "1.0.0")]
        [InlineData("What-Is-A.FooPackage.10.0.1", "10.0.1")]
        [InlineData("What-Is-A.FooPackage.10.0.1-beta.final", "10.0.1-beta.final")]
        [InlineData("What-Is-A.FooPackage.10.0.1-preview1.12345.1", "10.0.1-preview1.12345.1")]
        [InlineData("What-Is-A.FooPackage.2.2.1.0.0", "1.0.0")]
        [InlineData("What-Is-A.FooPackage.2.2.10.0.1", "10.0.1")]
        [InlineData("What-Is-A.FooPackage.2.2.10.0.1-beta.final", "10.0.1-beta.final")]
        [InlineData("What-Is-A.FooPackage.2.2.10.0.1-preview1.12345.1", "10.0.1-preview1.12345.1")]
        [InlineData("What-Is-A.FooPackage", null)]
        [InlineData("What-Is-A.FooPackage-2.2-64", null)]
        [InlineData("What-Is-A.FooPackage-2.2.nupkg", null)]
        public void ValidateSimpleVersions(string assetName, string version)
        {
            Assert.Equal(version, VersionIdentifier.GetVersion(assetName));
        }

        [Fact]
        public void ValidateVersions()
        {
            List<VersionIdentifierTestAsset> testAssets = GetTestAssets();

            foreach (VersionIdentifierTestAsset testAsset in testAssets)
            {
                Assert.Equal($"{testAsset.Name} has version {testAsset.ExpectedVersion}", $"{testAsset.Name} has version {VersionIdentifier.GetVersion(testAsset.Name)}");
            }
        }

        private List<VersionIdentifierTestAsset> GetTestAssets()
        {
            List<VersionIdentifierTestAsset> testAssets = new List<VersionIdentifierTestAsset>();
            string[] assets = File.ReadAllLines("BuildManifest/VersionIdentifierTestsAssets.csv");

            foreach (string input in assets)
            {
                if (!string.IsNullOrEmpty(input))
                {
                    string[] values = input.Split(',');
                    string name = values[0];
                    string expectedVersion = string.IsNullOrEmpty(values[1]) ? null : values[1];
                    // string nameWithoutVersions = string.IsNullOrEmpty(values[2]) ? null : values[2];
                    string nameWithoutVersions = null;
                    testAssets.Add(new VersionIdentifierTestAsset(name, expectedVersion, nameWithoutVersions));
                }
            }

            return testAssets;
        }
    }
}
