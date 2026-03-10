// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.DotNet.RecursiveSigning.Abstractions;
using Microsoft.DotNet.RecursiveSigning.Models;

namespace Microsoft.DotNet.RecursiveSigning.Implementation
{
    /// <summary>
    /// Serializes a completed <see cref="ISigningGraph"/> into a JSON signing report
    /// that describes each file's certificate selection, parent container relationships,
    /// certificate details, and provider-specific signing operation data.
    /// </summary>
    public static class SigningGraphSerializer
    {
        private static readonly JsonSerializerOptions s_jsonOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        /// <summary>
        /// Serialize the signing graph into a JSON string.
        /// </summary>
        public static string Serialize(ISigningGraph signingGraph)
        {
            if (signingGraph == null) throw new ArgumentNullException(nameof(signingGraph));

            var allNodes = signingGraph.GetAllNodes();
            var files = new List<Dictionary<string, object?>>();
            var certificates = new Dictionary<string, object?>();

            foreach (var node in allNodes)
            {
                var entry = BuildFileEntry(node);
                files.Add(entry);

                // Collect unique certificate details
                var certId = node.CertificateIdentifier;
                if (certId != null && !certificates.ContainsKey(certId.Name))
                {
                    certificates[certId.Name] = certId.SerializeDetails();
                }
            }

            var report = new Dictionary<string, object?>
            {
                ["files"] = files,
                ["certificates"] = certificates,
            };

            return JsonSerializer.Serialize(report, s_jsonOptions);
        }

        private static Dictionary<string, object?> BuildFileEntry(FileNodeBase node)
        {
            var entry = new Dictionary<string, object?>
            {
                ["path"] = node.Location.FilePathOnDisk,
                ["fileName"] = node.ContentKey.FileName,
                ["state"] = node.State.ToString(),
                ["isContainer"] = node.IsContainer,
            };

            if (node.Location.RelativePathInContainer != null)
            {
                entry["pathInContainer"] = node.Location.RelativePathInContainer;
            }

            if (node.Parent != null)
            {
                entry["parentContainer"] = node.Parent.Location.FilePathOnDisk;
            }

            if (node.CertificateIdentifier != null)
            {
                entry["certificate"] = node.CertificateIdentifier.Name;
            }

            if (node is ReferenceNode refNode)
            {
                entry["isDuplicate"] = true;
                entry["canonicalPath"] = refNode.CanonicalNode.Location.FilePathOnDisk;
            }

            if (node.SigningDetails != null)
            {
                var details = new Dictionary<string, object?>
                {
                    ["providerName"] = node.SigningDetails.ProviderName,
                };
                foreach (var kv in node.SigningDetails.GetDetails())
                {
                    details[kv.Key] = kv.Value;
                }
                entry["signingDetails"] = details;
            }

            if (node.IsContainer && node.Children.Count > 0)
            {
                entry["childCount"] = node.Children.Count;
                entry["children"] = node.Children.Select(c => c.ContentKey.FileName).ToList();
            }

            return entry;
        }
    }
}
