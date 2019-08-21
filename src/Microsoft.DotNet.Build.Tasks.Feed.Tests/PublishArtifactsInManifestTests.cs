// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System;
using System.Collections.Generic;
using Xunit;

namespace Microsoft.DotNet.Build.Tasks.Feed.Tests
{
    public class PublishArtifactsInManifestTests
    {
        const string RandomToken = "abcd";
        const string BlobFeedUrl = "https://dotnetfeed.blob.core.windows.net/dotnet-core/index.json";

        [Fact]
        public void FeedConfigParserTests1()
        {
            var task = new PublishArtifactsInManifest
            {
                // Create a single ITaskItem for a simple feed config, then parse to FeedConfigs and
                // check the expected values.
                TargetFeedConfig = new TaskItem[]
                {
                    new TaskItem("FOOPACKAGES", new Dictionary<string, string> {
                        { "TargetUrl", BlobFeedUrl },
                        { "Token", RandomToken },
                        { "Type", "AzDoNugetFeed" }}),
                },
            };

            var outputConfigs = task.ParseTargetFeedConfig();
            Assert.Collection(outputConfigs,
                configList =>
                {
                    Assert.Equal("FOOPACKAGES", configList.Key);
                    Assert.Collection(configList.Value, config =>
                    {
                        Assert.Equal(RandomToken, config.FeedKey);
                        Assert.Equal(BlobFeedUrl, config.TargetFeedURL);
                        Assert.Equal(FeedType.AzDoNugetFeed, config.Type);
                        Assert.Equal(AssetSelection.All, config.AssetSelection);
                    });
                });
        }
    }
}
