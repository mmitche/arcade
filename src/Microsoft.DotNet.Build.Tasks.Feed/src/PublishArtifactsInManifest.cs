// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Amazon.Runtime.Internal.Transform;
using Amazon.Runtime.Internal.Util;
using Amazon.S3.Model;
using Microsoft.Build.Framework;
using Microsoft.DotNet.Maestro.Client;
using Microsoft.DotNet.Maestro.Client.Models;
using Microsoft.DotNet.VersionTools.BuildManifest.Model;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MSBuild = Microsoft.Build.Utilities;

namespace Microsoft.DotNet.Build.Tasks.Feed
{
    /// <summary>
    /// The intended use of this task is to push artifacts described in
    /// a build manifest to a static package feed.
    /// </summary>
    public class PublishArtifactsInManifest : MSBuild.Task
    {
        /// <summary>
        /// Configuration telling which target feed to use for each artifact category.
        /// ItemSpec: ArtifactCategory
        /// Metadata TargetURL: target URL where assets of this category should be published to.
        /// Metadata Type: type of the target feed.
        /// Metadata Token: token to be used for publishing to target feed.
        /// </summary>
        [Required]
        public ITaskItem[] TargetFeedConfig { get; set; }

        /// <summary>
        /// Full path to the assets to publish manifest.
        /// </summary>
        [Required]
        public string AssetManifestPath { get; set; }

        /// <summary>
        /// Full path to the folder containing blob assets.
        /// </summary>
        [Required]
        public string BlobAssetsBasePath { get; set; }

        /// <summary>
        /// Full path to the folder containing package assets.
        /// </summary>
        [Required]
        public string PackageAssetsBasePath { get; set; }

        /// <summary>
        /// ID of the build (in BAR/Maestro) that produced the artifacts being published.
        /// This might change in the future as we'll probably fetch this ID from the manifest itself.
        /// </summary>
        [Required]
        public int BARBuildId { get; set; }

        /// <summary>
        /// Access point to the Maestro API to be used for accessing BAR.
        /// </summary>
        [Required]
        public string MaestroApiEndpoint { get; set; }

        /// <summary>
        /// Authentication token to be used when interacting with Maestro API.
        /// </summary>
        [Required]
        public string BuildAssetRegistryToken { get; set; }

        /// <summary>
        /// Maximum number of parallel uploads for the upload tasks
        /// </summary>
        public int MaxClients { get; set; } = 8;

        /// <summary>
        /// Directory where "nuget.exe" is installed. This will be used to publish packages.
        /// </summary>
        [Required]
        public string NugetPath { get; set; }

        public readonly Dictionary<string, List<FeedConfig>> FeedConfigs = new Dictionary<string, List<FeedConfig>>();

        private readonly Dictionary<string, List<PackageArtifactModel>> PackagesByCategory = new Dictionary<string, List<PackageArtifactModel>>();

        private readonly Dictionary<string, List<BlobArtifactModel>> BlobsByCategory = new Dictionary<string, List<BlobArtifactModel>>();


        public override bool Execute()
        {
            return ExecuteAsync().GetAwaiter().GetResult();
        }

        public async Task<bool> ExecuteAsync()
        {
            try
            {
                Log.LogMessage(MessageImportance.High, "Publishing artifacts to feed.");

                if (string.IsNullOrWhiteSpace(AssetManifestPath) || !File.Exists(AssetManifestPath))
                {
                    Log.LogError($"Problem reading asset manifest path from '{AssetManifestPath}'");
                }

                if (!Directory.Exists(BlobAssetsBasePath))
                {
                    Log.LogError($"Problem reading blob assets from {BlobAssetsBasePath}");
                }

                if (!Directory.Exists(PackageAssetsBasePath))
                {
                    Log.LogError($"Problem reading package assets from {PackageAssetsBasePath}");
                }

                var buildModel = BuildManifestUtil.ManifestFileToModel(AssetManifestPath, Log);

                // Parsing the manifest may fail for several reasons
                if (Log.HasLoggedErrors)
                {
                    return false;
                }

                // Fetch Maestro record of the build. We're going to use it to get the BAR ID
                // of the assets being published so we can add a new location for them.
                IMaestroApi client = ApiFactory.GetAuthenticated(MaestroApiEndpoint, BuildAssetRegistryToken);
                Maestro.Client.Models.Build buildInformation = await client.Builds.GetBuildAsync(BARBuildId);

                ParseTargetFeedConfig();

                // Return errors from parsing FeedConfig
                if (Log.HasLoggedErrors)
                {
                    return false;
                }

                SplitArtifactsInCategories(buildModel);

                await HandlePackagePublishingAsync(client, buildInformation);

                await HandleBlobPublishingAsync(client, buildInformation);
            }
            catch (Exception e)
            {
                Log.LogErrorFromException(e, true);
            }

            return !Log.HasLoggedErrors;
        }

        /// <summary>
        ///     Parse out the input TargetFeedConfig into a dictionary of FeedConfig types
        /// </summary>
        public void ParseTargetFeedConfig()
        {
            foreach (var fc in TargetFeedConfig)
            {
                string targetFeedUrl = fc.GetMetadata("TargetURL");
                string feedKey = fc.GetMetadata("Token");
                string type = fc.GetMetadata("Type");

                if (string.IsNullOrEmpty(targetFeedUrl) ||
                    string.IsNullOrEmpty(feedKey) ||
                    string.IsNullOrEmpty(type))
                {
                    Log.LogError($"Invalid FeedConfig entry. TargetURL='{targetFeedUrl}' Type='{type}' Token='{feedKey}'");
                    continue;
                }

                if (!Enum.TryParse<FeedType>(type, true, out FeedType feedType))
                {
                    Log.LogError($"Invalid feed config type '{type}'. Possible values are: {string.Join(", ", Enum.GetNames(typeof(FeedType)))}");
                    continue;
                }

                var feedConfig = new FeedConfig()
                {
                    TargetFeedURL = targetFeedUrl,
                    Type = feedType,
                    FeedKey = feedKey
                };

                string assetSelection = fc.GetMetadata("AssetSelection");
                if (!string.IsNullOrEmpty(assetSelection))
                {
                    if (!Enum.TryParse<AssetSelection>(assetSelection, true, out AssetSelection selection))
                    {
                        Log.LogError($"Invalid feed config asset selection '{type}'. Possible values are: {string.Join(", ", Enum.GetNames(typeof(AssetSelection)))}");
                        continue;
                    }
                    feedConfig.AssetSelection = selection;
                }

                string categoryKey = fc.ItemSpec.Trim().ToUpper();
                if (!FeedConfigs.TryGetValue(categoryKey, out var feedsList))
                {
                    FeedConfigs[categoryKey] = new List<FeedConfig>();
                }
                FeedConfigs[categoryKey].Add(feedConfig);
            }
        }

        private async Task HandlePackagePublishingAsync(IMaestroApi client, Maestro.Client.Models.Build buildInformation)
        {
            foreach (var packagesPerCategory in PackagesByCategory)
            {
                var category = packagesPerCategory.Key;
                var packages = packagesPerCategory.Value;

                if (FeedConfigs.TryGetValue(category, out List<FeedConfig> feedConfigsForCategory))
                {
                    foreach (var feedConfig in feedConfigsForCategory)
                    {
                        List<PackageArtifactModel> filteredPackages = FilterPackages(packages, feedConfig);

                        switch (feedConfig.Type)
                        {
                            case FeedType.AzDoNugetFeed:
                                await PublishPackagesToAzDoNugetFeedAsync(filteredPackages, client, buildInformation, feedConfig);
                                break;
                            case FeedType.AzureStorageFeed:
                                await PublishPackagesToAzureStorageNugetFeedAsync(filteredPackages, client, buildInformation, feedConfig);
                                break;
                            default:
                                Log.LogError($"Unknown target feed type for category '{category}': '{feedConfig.Type}'.");
                                break;
                        }
                    }
                }
                else
                {
                    Log.LogError($"No target feed configuration found for artifact category: '{category}'.");
                }
            }
        }

        private List<PackageArtifactModel> FilterPackages(List<PackageArtifactModel> packages, FeedConfig feedConfig)
        {
            // If the feed config wants further filtering, do that now.
            List<PackageArtifactModel> filteredPackages = null;
            switch (feedConfig.AssetSelection)
            {
                case AssetSelection.All:
                    // No filtering needed
                    filteredPackages = packages;
                    break;
                case AssetSelection.NonShippingOnly:
                    filteredPackages = packages.Where(p => p.NonShipping).ToList();
                    break;
                case AssetSelection.ShippingOnly:
                    filteredPackages = packages.Where(p => !p.NonShipping).ToList();
                    break;
                default:
                    // Throw NYI here instead of logging an error because error would have already been logged in the
                    // parser for the user.
                    throw new NotImplementedException("Unknown asset selection type '{feedConfig.AssetSelection}'");
            }

            return filteredPackages;
        }

        private async Task HandleBlobPublishingAsync(IMaestroApi client, Maestro.Client.Models.Build buildInformation)
        {
            foreach (var blobsPerCategory in BlobsByCategory)
            {
                var category = blobsPerCategory.Key;
                var blobs = blobsPerCategory.Value;

                if (FeedConfigs.TryGetValue(category, out List<FeedConfig> feedConfigsForCategory))
                {
                    foreach (var feedConfig in feedConfigsForCategory)
                    {
                        List<BlobArtifactModel> filteredBlobs = FilterBlobs(blobs, feedConfig);

                        switch (feedConfig.Type)
                        {
                            case FeedType.AzDoNugetFeed:
                                await PublishBlobsToAzDoNugetFeedAsync(filteredBlobs, client, buildInformation, feedConfig);
                                break;
                            case FeedType.AzureStorageFeed:
                                await PublishBlobsToAzureStorageNugetFeedAsync(filteredBlobs, client, buildInformation, feedConfig);
                                break;
                            default:
                                Log.LogError($"Unknown target feed type for category '{category}': '{feedConfig.Type}'.");
                                break;
                        }
                    }
                }
                else
                {
                    Log.LogError($"No target feed configuration found for artifact category: '{category}'.");
                }
            }
        }

        /// <summary>
        ///     Filter the blobs by the feed config information
        /// </summary>
        /// <param name="blobs"></param>
        /// <param name="feedConfig"></param>
        /// <returns></returns>
        private List<BlobArtifactModel> FilterBlobs(List<BlobArtifactModel> blobs, FeedConfig feedConfig)
        {
            // If the feed config wants further filtering, do that now.
            List<BlobArtifactModel> filteredBlobs = null;
            switch (feedConfig.AssetSelection)
            {
                case AssetSelection.All:
                    // No filtering needed
                    filteredBlobs = blobs;
                    break;
                case AssetSelection.NonShippingOnly:
                    filteredBlobs = blobs.Where(p => p.NonShipping).ToList();
                    break;
                case AssetSelection.ShippingOnly:
                    filteredBlobs = blobs.Where(p => !p.NonShipping).ToList();
                    break;
                default:
                    // Throw NYI here instead of logging an error because error would have already been logged in the
                    // parser for the user.
                    throw new NotImplementedException("Unknown asset selection type '{feedConfig.AssetSelection}'");
            }

            return filteredBlobs;
        }

        /// <summary>
        ///     Split the artifacts into categories.
        ///     
        ///     Categories are either specified explicitly when publishing (with the asset attribute "Category", separated by ';'),
        ///     or they are inferred based on the extension of the asset.
        /// </summary>
        /// <param name="buildModel"></param>
        private void SplitArtifactsInCategories(BuildModel buildModel)
        {
            foreach (var packageAsset in buildModel.Artifacts.Packages)
            {
                string categories = string.Empty;

                if (!packageAsset.Attributes.TryGetValue("Category", out categories))
                {
                    categories = InferCategory(packageAsset.Id);
                }

                foreach (var category in categories.Split(';').Select(c => c.ToUpper()))
                {
                    if (PackagesByCategory.ContainsKey(category))
                    {
                        PackagesByCategory[category].Add(packageAsset);
                    }
                    else
                    {
                        PackagesByCategory[category] = new List<PackageArtifactModel>() { packageAsset };
                    }
                }
            }

            foreach (var blobAsset in buildModel.Artifacts.Blobs)
            {
                string categories = string.Empty;

                if (!blobAsset.Attributes.TryGetValue("Category", out categories))
                {
                    categories = InferCategory(blobAsset.Id);
                }

                foreach (var category in categories.Split(';'))
                {
                    if (BlobsByCategory.ContainsKey(category))
                    {
                        BlobsByCategory[category].Add(blobAsset);
                    }
                    else
                    {
                        BlobsByCategory[category] = new List<BlobArtifactModel>() { blobAsset };
                    }
                }
            }
        }

        private async Task PublishPackagesToAzDoNugetFeedAsync(
            List<PackageArtifactModel> packagesToPublish,
            IMaestroApi client,
            Maestro.Client.Models.Build buildInformation,
            FeedConfig feedConfig)
        {
            // Filter packages down based on selection

            foreach (var package in packagesToPublish)
            {

                var assetRecord = buildInformation.Assets
                    .Where(a => a.Name.Equals(package.Id) && a.Version.Equals(package.Version))
                    .FirstOrDefault();

                if (assetRecord == null)
                {
                    Log.LogError($"Asset with Id {package.Id}, Version {package.Version} isn't registered on the BAR Build with ID {BARBuildId}");
                    continue;
                }

                var assetWithLocations = await client.Assets.GetAssetAsync(assetRecord.Id);

                if (assetWithLocations?.Locations.Any(al => al.Location.Equals(feedConfig.TargetFeedURL, StringComparison.OrdinalIgnoreCase)) ?? false)
                {
                    Log.LogMessage($"Asset with Id {package.Id}, Version {package.Version} already has location {feedConfig.TargetFeedURL}");
                    continue;
                }

                await client.Assets.AddAssetLocationToAssetAsync(assetRecord.Id, AddAssetLocationToAssetAssetLocationType.NugetFeed, feedConfig.TargetFeedURL);
            }

            await PushNugetPackagesAsync(packagesToPublish, feedConfig, maxClients: MaxClients);
        }

        public Task<int> StartProcessAsync(string path, string arguments)
        {
            ProcessStartInfo info = new ProcessStartInfo(path, arguments);
            Process process = new Process
            {
                StartInfo = info
            };

            var completionSource = new TaskCompletionSource<int>();

            process.Exited += (obj, args) =>
            {
                completionSource.SetResult(((Process)obj).ExitCode);
                process.Dispose();
            };

            process.ErrorDataReceived += (obj, args) =>
            {
                Log.LogMessage(MessageImportance.High, args.Data);
            };

            process.OutputDataReceived += (obj, args) =>
            {
                Log.LogMessage(MessageImportance.Low, args.Data);
            };

            process.Start();

            return completionSource.Task;
        }

        /// <summary>
        ///     Push nuget packages to the azure devops feed.
        /// </summary>
        /// <param name="packagesToPublish"></param>
        /// <param name="feedConfig"></param>
        /// <returns></returns>
        public async Task PushNugetPackagesAsync(List<PackageArtifactModel> packagesToPublish, FeedConfig feedConfig, int maxClients)
        {
            var localPackageFiles = packagesToPublish.Select(p => $"{PackageAssetsBasePath}{p.Id}.{p.Version}.nupkg");
            foreach (var packageToPublish in localPackageFiles)
            {
                using (var clientThrottle = new SemaphoreSlim(maxClients, maxClients))
                {
                    try
                    {
                        // Wait to avoid starting too many processes.
                        await clientThrottle.WaitAsync();
                        Log.LogMessage(MessageImportance.High, $"Pushing package '{packageToPublish}' to feed {feedConfig.TargetFeedURL}");
                        int result = await StartProcessAsync(NugetPath, $"push \"{packageToPublish}\"-Source \"{feedConfig.TargetFeedURL}\" -ApiKey \"{feedConfig.FeedKey}\"");
                        if (result != 0)
                        {
                            Log.LogError($"Failed to push '{packageToPublish}'.");
                        }
                    }
                    finally
                    {
                        clientThrottle.Release();
                    }
                }
            }
        }

        private async Task PublishBlobsToAzDoNugetFeedAsync(
            List<BlobArtifactModel> blobsToPublish,
            IMaestroApi client,
            Maestro.Client.Models.Build buildInformation,
            FeedConfig feedConfig)
        {
            foreach (var blob in blobsToPublish)
            {
                var assetRecord = buildInformation.Assets
                    .Where(a => a.Name.Equals(blob.Id))
                    .FirstOrDefault();

                if (assetRecord == null)
                {
                    Log.LogError($"Asset with Id {blob.Id} isn't registered on the BAR Build with ID {BARBuildId}");
                    continue;
                }

                var assetWithLocations = await client.Assets.GetAssetAsync(assetRecord.Id);

                if (assetWithLocations?.Locations.Any(al => al.Location.Equals(feedConfig.TargetFeedURL, StringComparison.OrdinalIgnoreCase)) ?? false)
                {
                    Log.LogMessage($"Asset with Id {blob.Id} already has location {feedConfig.TargetFeedURL}");
                    continue;
                }

                await client.Assets.AddAssetLocationToAssetAsync(assetRecord.Id, AddAssetLocationToAssetAssetLocationType.Container, feedConfig.TargetFeedURL);
            }
        }

        private async Task PublishPackagesToAzureStorageNugetFeedAsync(
            List<PackageArtifactModel> packagesToPublish,
            IMaestroApi client,
            Maestro.Client.Models.Build buildInformation,
            FeedConfig feedConfig)
        {
            PackageAssetsBasePath = PackageAssetsBasePath.TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar) 
                + Path.DirectorySeparatorChar;

            var packages = packagesToPublish.Select(p => $"{PackageAssetsBasePath}{p.Id}.{p.Version}.nupkg");
            var blobFeedAction = CreateBlobFeedAction(feedConfig);

            var pushOptions = new PushOptions
            {
                AllowOverwrite = false,
                PassIfExistingItemIdentical = true
            };

            foreach (var package in packagesToPublish)
            {
                var assetRecord = buildInformation.Assets
                    .Where(a => a.Name.Equals(package.Id) && a.Version.Equals(package.Version))
                    .FirstOrDefault();

                if (assetRecord == null)
                {
                    Log.LogError($"Asset with Id {package.Id}, Version {package.Version} isn't registered on the BAR Build with ID {BARBuildId}");
                    continue;
                }

                var assetWithLocations = await client.Assets.GetAssetAsync(assetRecord.Id);

                if (assetWithLocations?.Locations.Any(al => al.Location.Equals(feedConfig.TargetFeedURL, StringComparison.OrdinalIgnoreCase)) ?? false)
                {
                    Log.LogMessage($"Asset with Id {package.Id}, Version {package.Version} already has location {feedConfig.TargetFeedURL}");
                    continue;
                }

                await client.Assets.AddAssetLocationToAssetAsync(assetRecord.Id, AddAssetLocationToAssetAssetLocationType.NugetFeed, feedConfig.TargetFeedURL);
            }

            await blobFeedAction.PushToFeedAsync(packages, pushOptions);
        }

        private async Task PublishBlobsToAzureStorageNugetFeedAsync(
            List<BlobArtifactModel> blobsToPublish,
            IMaestroApi client,
            Maestro.Client.Models.Build buildInformation,
            FeedConfig feedConfig)
        {
            BlobAssetsBasePath = BlobAssetsBasePath.TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar) 
                + Path.DirectorySeparatorChar;

            var blobs = blobsToPublish
                .Select(blob =>
                {
                    var fileName = Path.GetFileName(blob.Id);
                    return new MSBuild.TaskItem($"{BlobAssetsBasePath}{fileName}", new Dictionary<string, string>
                    {
                        {"RelativeBlobPath", blob.Id}
                    });
                })
                .ToArray();

            var blobFeedAction = CreateBlobFeedAction(feedConfig);
            var pushOptions = new PushOptions
            {
                AllowOverwrite = false,
                PassIfExistingItemIdentical = true
            };

            foreach (var blob in blobsToPublish)
            {
                var assetRecord = buildInformation.Assets
                    .Where(a => a.Name.Equals(blob.Id))
                    .SingleOrDefault();

                if (assetRecord == null)
                {
                    Log.LogError($"Asset with Id {blob.Id} isn't registered on the BAR Build with ID {BARBuildId}");
                    continue;
                }

                var assetWithLocations = await client.Assets.GetAssetAsync(assetRecord.Id);

                if (assetWithLocations?.Locations.Any(al => al.Location.Equals(feedConfig.TargetFeedURL, StringComparison.OrdinalIgnoreCase)) ?? false)
                {
                    Log.LogMessage($"Asset with Id {blob.Id} already has location {feedConfig.TargetFeedURL}");
                    continue;
                }

                await client.Assets.AddAssetLocationToAssetAsync(assetRecord.Id, AddAssetLocationToAssetAssetLocationType.Container, feedConfig.TargetFeedURL);
            }

            await blobFeedAction.PublishToFlatContainerAsync(blobs, maxClients: MaxClients, pushOptions);
        }

        private BlobFeedAction CreateBlobFeedAction(FeedConfig feedConfig)
        {
            // Matches package feeds like
            // https://dotnet-feed-internal.azurewebsites.net/container/dotnet-core-internal/sig/dsdfasdfasdf234234s/se/2020-02-02/darc-int-dotnet-arcade-services-babababababe-08/index.json
            const string azureStorageProxyFeedPattern =
                @"(?<feedURL>https://([a-z-]+).azurewebsites.net/container/(?<container>[^/]+)/sig/\w+/se/([0-9]{4}-[0-9]{2}-[0-9]{2})/(?<baseFeedName>darc-(?<type>int|pub)-(?<repository>.+?)-(?<sha>[A-Fa-f0-9]{7,40})-?(?<subversion>\d*)/))index.json";

            // Matches package feeds like the one below. Special case for static internal proxy-backed feed
            // https://dotnet-feed-internal.azurewebsites.net/container/dotnet-core-internal/sig/dsdfasdfasdf234234s/se/2020-02-02/darc-int-dotnet-arcade-services-babababababe-08/index.json
            const string azureStorageProxyFeedStaticPattern =
                @"(?<feedURL>https://([a-z-]+).azurewebsites.net/container/(?<container>[^/]+)/sig/\w+/se/([0-9]{4}-[0-9]{2}-[0-9]{2})/(?<baseFeedName>[^/]+/))index.json";

            // Matches package feeds like
            // https://dotnetfeed.blob.core.windows.net/dotnet-core/index.json
            const string azureStorageStaticBlobFeedPattern =
                @"https://([a-z-]+).blob.core.windows.net/[^/]+/index.json";

            var proxyBackedFeedMatch = Regex.Match(feedConfig.TargetFeedURL, azureStorageProxyFeedPattern);
            var proxyBackedStaticFeedMatch = Regex.Match(feedConfig.TargetFeedURL, azureStorageProxyFeedStaticPattern);
            var azureStorageStaticBlobFeedMatch = Regex.Match(feedConfig.TargetFeedURL, azureStorageStaticBlobFeedPattern);

            if (proxyBackedFeedMatch.Success || proxyBackedStaticFeedMatch.Success)
            {
                var regexMatch = (proxyBackedFeedMatch.Success) ? proxyBackedFeedMatch : proxyBackedStaticFeedMatch;
                var containerName = regexMatch.Groups["container"].Value;
                var baseFeedName = regexMatch.Groups["baseFeedName"].Value;
                var feedURL = regexMatch.Groups["feedURL"].Value;
                var storageAccountName = "dotnetfeed";

                // Initialize the feed using sleet
                SleetSource sleetSource = new SleetSource()
                {
                    Name = baseFeedName,
                    Type = "azure",
                    BaseUri = feedURL,
                    AccountName = storageAccountName,
                    Container = containerName,
                    FeedSubPath = baseFeedName,
                    ConnectionString = $"DefaultEndpointsProtocol=https;AccountName={storageAccountName};AccountKey={feedConfig.FeedKey};EndpointSuffix=core.windows.net"
                };

                return new BlobFeedAction(sleetSource, feedConfig.FeedKey, Log);
            }
            else if (azureStorageStaticBlobFeedMatch.Success)
            {
                return new BlobFeedAction(feedConfig.TargetFeedURL, feedConfig.FeedKey, Log);
            }
            else
            {
                Log.LogError($"Could not parse Azure feed URL: '{feedConfig.TargetFeedURL}'");
                return null;
            }
        }

        /// <summary>
        ///     Infers the category based on the extension of the particular asset
        ///     
        ///     If no category can be inferred, then "NETCORE" is used.
        /// </summary>
        /// <param name="assetId">ID of asset</param>
        /// <returns>Asset cateogry</returns>
        private string InferCategory(string assetId)
        {
            var extension = Path.GetExtension(assetId).ToUpper();

            var whichCategory = new Dictionary<string, string>()
            {
                { ".NUPKG", "NETCORE" },
                { ".PKG", "OSX" },
                { ".DEB", "DEB" },
                { ".RPM", "RPM" },
                { ".NPM", "NODE" },
                { ".ZIP", "BINARYLAYOUT" },
                { ".MSI", "INSTALLER" },
                { ".SHA", "CHECKSUM" },
                { ".POM", "MAVEN" },
                { ".VSIX", "VSIX" },
            };

            if (whichCategory.TryGetValue(extension, out var category))
            {
                return category;
            }
            else
            {
                return "NETCORE";
            }
        }
    }

    public enum FeedType
    {
        AzDoNugetFeed,
        AzureStorageFeed
    }

    /// <summary>
    ///     Which assets from the category should be
    ///     added to the feed.
    /// </summary>
    public enum AssetSelection
    {
        All,
        ShippingOnly,
        NonShippingOnly
    }

    /// <summary>
    /// Hold properties of a target feed endpoint.
    /// </summary>
    public class FeedConfig
    {
        public string TargetFeedURL { get; set; }
        public FeedType Type { get; set; }
        public string FeedKey { get; set; }
        public AssetSelection AssetSelection { get; set; } = AssetSelection.All;
    }
}
