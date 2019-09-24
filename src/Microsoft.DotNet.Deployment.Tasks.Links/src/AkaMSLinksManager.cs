// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

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

        private string _clientId;
        private string _clientSecret;
        private string _tenant;
        private string ApiTargeturl { get => $"{ApiBaseUrl}/1/{_tenant}"; }

        public AkaMSLinkManager(string clientId, string clientSecret, string tenant)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _tenant = tenant;
        }

        /// <summary>
        /// Delete one or more aka.ms links
        /// </summary>
        /// <param name="linksToDelete">Links to delete. Should not be prefixed with 'aka.ms'</param>
        /// <returns>Async task</returns>
        public async Task DeleteLinksAsync(IEnumerable<string> linksToDelete)
        {
            using (HttpClient client = CreateClient())
            {
                await Task.WhenAll(linksToDelete.Select(async link =>
                {
                    var response = await client.DeleteAsync($"{ApiTargeturl}/{link}");
                    // Success if it's 202, 204, 404
                    if (response.StatusCode != System.Net.HttpStatusCode.NoContent &&
                        response.StatusCode != System.Net.HttpStatusCode.NotFound &&
                        response.StatusCode != System.Net.HttpStatusCode.Accepted)
                    {
                        throw new Exception($"Failed to delete aka.ms/{link}: {response.Content.ReadAsStringAsync().Result}");
                    }
                }));
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
        public async Task CreateLinksAsync(List<AkaMSLink> links, string owners, string createdBy, string groupOwner, bool overwrite)
        {
            using (HttpClient client = CreateClient())
            {
                // Final of links that need creation. If existing links point to the same place,
                // then links 
                ConcurrentBag<AkaMSLink> linksToCreate = new ConcurrentBag<AkaMSLink>();
                ConcurrentBag<AkaMSLink> linksToUpdate = new ConcurrentBag<AkaMSLink>();

                await Task.WhenAll(linksToCreate.Select(async link =>
                {
                    HttpResponseMessage existsCheck = await client.GetAsync($"{ApiTargeturl}/{link.ShortUrl}");
                    if (existsCheck.StatusCode != System.Net.HttpStatusCode.NotFound)
                    {
                        if (!existsCheck.IsSuccessStatusCode)
                        {
                            throw new Exception($"aka.ms GET api returned unexpected result: {existsCheck.Content.ReadAsStringAsync().Result}");
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
                                // Will not overwrite an existing link that does not already point to the target location
                                throw new Exception($"aka.ms/{link.ShortUrl} exists but doesn't target {link.TargetUrl}, skipping update.");
                            }
                        }
                    }
                    else
                    {
                        linksToCreate.Add(link);
                    }
                }));

                // Now create all new links
                await Task.WhenAll(linksToCreate.Select(async link =>
                {
                    var newLink = new
                    {
                        isVanity = !string.IsNullOrEmpty(link.ShortUrl),
                        shortUrl = link.ShortUrl,
                        owners = _owners,
                        targetUrl = link.TargetUrl,
                        createdBy = _createdBy,
                        lastModifiedBy = _createdBy,
                        description = link.Description,
                        groupOwner = _groupOwner
                    };

                    var response = await client.PostAsync(ApiTargeturl,
                        new StringContent(JsonConvert.SerializeObject(newLink), Encoding.UTF8, "application/json"));
                    
                    if (response.StatusCode != System.Net.HttpStatusCode.Created)
                    {
                        throw new Exception($"Error creating aka.ms/{link.ShortUrl}->{link.TargetUrl} link: {response.Content.ReadAsStringAsync().Result}");
                    }
                }));

                // And update existing ones
                await Task.WhenAll(linksToUpdate.Select(async link =>
                {
                    // Create the POST body
                    var updateLink = new
                    {
                        targetUrl = link.TargetUrl,
                        owners = _owners,
                        lastModifiedBy = _createdBy
                    };

                    var response = await client.PutAsync($"{ApiTargeturl}/{link.ShortUrl}",
                        new StringContent(JsonConvert.SerializeObject(updateLink), Encoding.UTF8, "application/json"));

                    // Supposedly 404 is a successful status code for an update (link not found), but that seems really
                    // odd so it is excluded from the valid status codes.
                    if (response.StatusCode != System.Net.HttpStatusCode.Accepted &&
                        response.StatusCode != System.Net.HttpStatusCode.NoContent)
                    {
                        throw new Exception($"Error updating aka.ms/{link.ShortUrl}->{link.TargetUrl} link: {response.Content.ReadAsStringAsync().Result}");
                    }
                }));
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
