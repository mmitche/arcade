// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Build.Utilities;
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
            var buildEngine = new MockBuildEngine();
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
                BuildEngine = buildEngine
            };

            task.ParseTargetFeedConfig();
            Assert.False(task.Log.HasLoggedErrors);

            // This will have set the feed configs.
            Assert.Collection(task.FeedConfigs,
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

        [Fact]
        public void FeedConfigParserTests2()
        {
            var buildEngine = new MockBuildEngine();
            var task = new PublishArtifactsInManifest
            {
                TargetFeedConfig = new TaskItem[]
                {
                    new TaskItem("FOOPACKAGES", new Dictionary<string, string> {
                        { "TargetUrl", BlobFeedUrl },
                        { "Token", RandomToken },
                        { "Type", "MyUnknownFeedType" } }),
                },
                BuildEngine = buildEngine
            };

            task.ParseTargetFeedConfig();
            Assert.True(task.Log.HasLoggedErrors);
            Assert.Contains(buildEngine.BuildErrorEvents, e => e.Message.Equals("Invalid feed config type 'MyUnknownFeedType'. Possible values are: AzDoNugetFeed, AzureStorageFeed"));
        }

        [Fact]
        public void FeedConfigParserTests3()
        {
            var buildEngine = new MockBuildEngine();
            var task = new PublishArtifactsInManifest
            {
                TargetFeedConfig = new TaskItem[]
                {
                    new TaskItem("FOOPACKAGES", new Dictionary<string, string> {
                        { "TargetUrl", string.Empty },
                        { "Token", string.Empty },
                        { "Type", string.Empty } }),
                },
                BuildEngine = buildEngine
            };

            task.ParseTargetFeedConfig();
            Assert.True(task.Log.HasLoggedErrors);
            Assert.Contains(buildEngine.BuildErrorEvents, e => e.Message.Equals("Invalid FeedConfig entry. TargetURL='' Type='' Token=''"));
        }

        /// <summary>
        ///     Valid feed config with an asset selection set.
        /// </summary>
        [Fact]
        public void FeedConfigParserTests4()
        {
            var buildEngine = new MockBuildEngine();
            var task = new PublishArtifactsInManifest
            {
                TargetFeedConfig = new TaskItem[]
                {
                    new TaskItem("FOOPACKAGES", new Dictionary<string, string> {
                        { "TargetUrl", BlobFeedUrl },
                        { "Token", RandomToken },
                        { "Type", "AZURESTORAGEFEED" },
                        { "AssetSelection", "SHIPPINGONLY" }}),
                },
                BuildEngine = buildEngine
            };

            task.ParseTargetFeedConfig();

            // This will have set the feed configs.
            Assert.Collection(task.FeedConfigs,
                configList =>
                {
                    Assert.Equal("FOOPACKAGES", configList.Key);
                    Assert.Collection(configList.Value, config =>
                    {
                        Assert.Equal(RandomToken, config.FeedKey);
                        Assert.Equal(BlobFeedUrl, config.TargetFeedURL);
                        Assert.Equal(FeedType.AzureStorageFeed, config.Type);
                        Assert.Equal(AssetSelection.ShippingOnly, config.AssetSelection);
                    });
                });
        }
    }
}
