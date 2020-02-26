// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Build.Framework;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.DotNet.VersionTools.Util;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Net;

namespace Microsoft.DotNet.Deployment.Tasks.Links.src
{
    /// <summary>
    ///     A single aka.ms link.
    /// </summary>
    public class AkaMSLink
    {
        /// <summary>
        /// Target of the link
        /// </summary>
        public string TargetUrl { get; set; }
        /// <summary>
        /// Short url of the link. Should only include the fragment element of the url, not the full aka.ms
        /// link.
        /// </summary>
        public string ShortUrl { get; set; }
        /// <summary>
        /// Description of the link.
        /// </summary>
        public string Description { get; set; } = "";
    }

    public class AkaMSLinkManager
    {
        private const string ApiBaseUrl = "https://redirectionapi.trafficmanager.net/api/aka";
        private const string Endpoint = "https://microsoft.onmicrosoft.com/redirectionapi";
        private const string Authority = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/authorize";
        private const int BulkApiBatchSize = 300;

        private string _clientId;
        private string _clientSecret;
        private string _tenant;
        private string ApiTargeturl { get => $"{ApiBaseUrl}/1/{_tenant}"; }

        private Microsoft.Build.Utilities.TaskLoggingHelper _log;

        public AkaMSLinkManager(string clientId, string clientSecret, string tenant, Microsoft.Build.Utilities.TaskLoggingHelper log)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _tenant = tenant;
            _log = log;
        }

        /// <summary>
        /// Delete one or more aka.ms links
        /// </summary>
        /// <param name="linksToDelete">Links to delete. Should not be prefixed with 'aka.ms'</param>
        /// <returns>Async task</returns>
        public async Task DeleteLinksAsync(List<string> linksToDelete)
        {
            var retryHandler = new ExponentialRetry
            {
                MaxAttempts = 5
            };

            using (HttpClient client = CreateClient())
            {
                // The links should be divided into BulkApiBatchSize element chunks
                var currentElement = 0;
                var batchOfLinksToDelete = linksToDelete.Skip(currentElement).Take(BulkApiBatchSize).ToList();

                while (batchOfLinksToDelete.Count > 0)
                {
                    bool success = await retryHandler.RunAsync(async attempt =>
                    {
                        // Use the bulk deletion API. The bulk APIs only work for up to 300 items per call.
                        // So batch
                        var response = await client.PutAsync($"{ApiTargeturl}/deactivate/bulk",
                            new StringContent(JsonConvert.SerializeObject(linksToDelete), Encoding.UTF8, "application/json"));

                        // 400, 401, and 403 indicate auth failure or bad requests that should not be retried.
                        // Check for auth failures/bad request on POST (400, 401, and 403)
                        if (response.StatusCode == HttpStatusCode.BadRequest ||
                            response.StatusCode == HttpStatusCode.Unauthorized ||
                            response.StatusCode == HttpStatusCode.Forbidden)
                        {
                            _log.LogError($"Error deleting aka.ms links: {response.StatusCode}");
                            return true;
                        }

                        // Success if it's 202, 204, 404
                        if (response.StatusCode != System.Net.HttpStatusCode.NoContent &&
                            response.StatusCode != System.Net.HttpStatusCode.NotFound &&
                            response.StatusCode != System.Net.HttpStatusCode.Accepted)
                        {
                            _log.LogMessage(MessageImportance.High, $"Failed to delete aka.ms links: {response.Content.ReadAsStringAsync().Result}");
                            return false;
                        }

                        return true;
                    });

                    currentElement += BulkApiBatchSize;
                    batchOfLinksToDelete = linksToDelete.Skip(currentElement).Take(BulkApiBatchSize).ToList();
                }
            }
        }

        /// <summary>
        /// Create one or more links
        /// </summary>
        /// <param name="links">Set of links to create or update</param>
        /// <param name="overwrite">If the links exist already, should they be overwritten?</param>
        /// <returns>Async task</returns>
        /// <remarks>
        /// If overwrite != true, CreateLinks will first evaluate all desired links to determine whether
        /// any exist. Only if all can be created will any be created. If an existing link points to the desired target,
        /// it is not updated and there is no error (even if overwrite == false).
        /// </remarks>
        public async Task CreateLinksAsync(List<AkaMSLink> links, string linkOwners, string linkCreatedBy, string linkGroupOwner, bool overwrite)
        {
            var retryHandler = new ExponentialRetry
            {
                MaxAttempts = 5
            };

            using (HttpClient client = CreateClient())
            {
                // Final of links that need creation or update. If existing links point to the same place,
                // then no change is made. We need to bucket and determine whether we need to update or
                // create the links
                ConcurrentBag<AkaMSLink> linksToCreate = new ConcurrentBag<AkaMSLink>();
                ConcurrentBag<AkaMSLink> linksToUpdate = new ConcurrentBag<AkaMSLink>();

                /*await Task.WhenAll(links.Select(async link =>
                {
                    bool success = await retryHandler.RunAsync(async attempt =>
                    {
                        HttpResponseMessage existsCheck = await client.GetAsync($"{ApiTargeturl}/{link.ShortUrl}");
                        if (existsCheck.StatusCode != HttpStatusCode.NotFound)
                        {
                            // Retry on anything but auth failures. GET can retrurn 401 and 403
                            if (existsCheck.StatusCode == HttpStatusCode.Unauthorized || 
                                existsCheck.StatusCode == HttpStatusCode.Forbidden)
                            {
                                _log.LogError($"Failed to determine whether {link.ShortUrl} exists: {existsCheck.StatusCode}");
                                return true;
                            }

                            // Otherwise, we retry on other failure codes.
                            if (!existsCheck.IsSuccessStatusCode)
                            {
                                _log.LogMessage(MessageImportance.High, $"Unable to determine whether {link.ShortUrl} exists, GET {ApiTargeturl}/{link.ShortUrl} returned {existsCheck.StatusCode}. Retrying");
                                return false;
                            }

                            var existingLink = Newtonsoft.Json.Linq.JObject.Parse(existsCheck.Content.ReadAsStringAsync().Result);
                            if ((string)existingLink["targetUrl"] != link.TargetUrl)
                            {
                                if (overwrite)
                                {
                                    linksToUpdate.Add(link);
                                }
                                else
                                {
                                    // Will not overwrite an existing link that does not already point to the target location. Fatal error,
                                    // but no retry
                                    _log.LogError($"aka.ms/{link.ShortUrl} exists but doesn't target {link.TargetUrl}, skipping update.");
                                }
                            }
                            else
                            {
                                _log.LogMessage(MessageImportance.High, $"Not changing link aka.ms/{link.ShortUrl}->{link.TargetUrl} (up to date)");
                            }
                        }
                        else
                        {
                            linksToCreate.Add(link);
                        }

                        return true;
                    });

                    if (!success)
                    {
                        _log.LogError($"Failed to create aka.ms link {link.ShortUrl}->{link.TargetUrl}");
                    }
                }));*/

                // The links should be divided into BulkApiBatchSize element chunks
                var currentElement = 0;
                var batchOfLinksToCreate = links.Skip(currentElement).Take(BulkApiBatchSize).ToList();

                while (batchOfLinksToCreate.Count > 0)
                {
                    // Now create all new links
                    var newLinks = batchOfLinksToCreate.Select(link =>
                    {
                        return new
                        {
                            // isVanity = !string.IsNullOrEmpty(link.ShortUrl),
                            shortUrl = link.ShortUrl,
                            owners = linkOwners,
                            targetUrl = link.TargetUrl,
                            // createdBy = linkCreatedBy,
                            lastModifiedBy = linkCreatedBy,
                            description = link.Description,
                            groupOwner = linkGroupOwner
                        };
                    });

                    string newLinksJson = JsonConvert.SerializeObject(newLinks);

                    bool success = await retryHandler.RunAsync(async attempt =>
                    {
                        _log.LogMessage(MessageImportance.High, $"Creating/Updating {batchOfLinksToCreate.Count} aka.ms links with body: {newLinksJson}");

                        var response = await client.PutAsync($"{ApiTargeturl}/bulk",
                            new StringContent(newLinksJson, Encoding.UTF8, "application/json"));

                        // Check for auth failures/bad request on POST (400, 401, and 403)
                        if (response.StatusCode == HttpStatusCode.BadRequest ||
                            response.StatusCode == HttpStatusCode.Unauthorized ||
                            response.StatusCode == HttpStatusCode.Forbidden)
                        {
                            _log.LogError($"Error creating aka.ms links: {response.StatusCode}");
                            return true;
                        }

                        if (response.StatusCode != System.Net.HttpStatusCode.Accepted &&
                            response.StatusCode != System.Net.HttpStatusCode.NoContent &&
                            response.StatusCode != System.Net.HttpStatusCode.NotFound)
                        {
                            _log.LogMessage(MessageImportance.High, $"Failed to create aka.ms links: {response.Content.ReadAsStringAsync().Result}");
                            return false;
                        }

                        return true;
                    });

                    if (!success)
                    {
                        _log.LogError($"Failed to create aka.ms links");
                    }

                    currentElement += BulkApiBatchSize;
                    batchOfLinksToCreate = links.Skip(currentElement).Take(BulkApiBatchSize).ToList();
                }

                // And update existing ones
                /*await Task.WhenAll(linksToUpdate.Select(async link =>
                {
                    // Create the POST body
                    var updateLink = new
                    {
                        targetUrl = link.TargetUrl,
                        owners = linkOwners,
                        lastModifiedBy = linkCreatedBy
                    };
                    var updateLinkJson = JsonConvert.SerializeObject(updateLink);

                    bool success = await retryHandler.RunAsync(async attempt =>
                    {
                        _log.LogMessage(MessageImportance.High, $"Error updating link aka.ms/{link.ShortUrl}->{link.TargetUrl}");

                        var response = await client.PutAsync($"{ApiTargeturl}/{link.ShortUrl}",
                            new StringContent(updateLinkJson, Encoding.UTF8, "application/json"));

                        // Check for auth failures/bad request on PUT (400, 401, and 403)
                        // Retry on anything but auth failures. GET can retrurn 400, 401 and 403
                        if (response.StatusCode == HttpStatusCode.BadRequest ||
                            response.StatusCode == HttpStatusCode.Unauthorized ||
                            response.StatusCode == HttpStatusCode.Forbidden)
                        {
                            _log.LogError($"Error updating aka.ms/{link.ShortUrl}->{link.TargetUrl} link: {response.StatusCode}");
                            return true;
                        }

                        // Supposedly 404 is a successful status code for an update (link not found), but that seems really
                        // odd so it is excluded from the valid status codes.
                        if (response.StatusCode != System.Net.HttpStatusCode.Accepted &&
                            response.StatusCode != System.Net.HttpStatusCode.NoContent)
                        {
                            _log.LogMessage(MessageImportance.High, $"Failed to create aka.ms/{link.ShortUrl}->{link.TargetUrl} link: {response.Content.ReadAsStringAsync().Result}");
                            return false;
                        }

                        return true;
                    });
                }));*/
            }
        }

        private HttpClient CreateClient()
        {
#if NETCOREAPP
            var platformParameters = new PlatformParameters();
#elif NETFRAMEWORK
            var platformParameters = new PlatformParameters(PromptBehavior.Auto);
#else
#error "Unexpected TFM"
#endif
            AuthenticationContext authContext = new AuthenticationContext(Authority);
            ClientCredential credential = new ClientCredential(_clientId, _clientSecret);
            AuthenticationResult token = authContext.AcquireTokenAsync(Endpoint, credential).Result;

            HttpClient httpClient = new HttpClient(new HttpClientHandler { CheckCertificateRevocationList = true });
            httpClient.DefaultRequestHeaders.Add("Authorization", token.CreateAuthorizationHeader());

            return httpClient;
        }
    }
}
