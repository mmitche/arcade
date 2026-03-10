// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.DotNet.RecursiveSigning.Abstractions;
using Microsoft.DotNet.RecursiveSigning.Implementation;
using Microsoft.DotNet.RecursiveSigning.Models;
using Moq;
using Xunit;

namespace Microsoft.DotNet.RecursiveSigning.Tests
{
    public class SigningGraphSerializerTests
    {
        private static readonly JsonSerializerOptions s_jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
        };

        [Fact]
        public void Serialize_EmptyGraph_ProducesEmptyReport()
        {
            var graph = new SigningGraph();
            graph.FinalizeDiscovery();

            var json = SigningGraphSerializer.Serialize(graph);
            var doc = JsonDocument.Parse(json);

            Assert.True(doc.RootElement.TryGetProperty("files", out var files));
            Assert.Equal(0, files.GetArrayLength());

            Assert.True(doc.RootElement.TryGetProperty("certificates", out var certs));
            Assert.Equal(JsonValueKind.Object, certs.ValueKind);
        }

        [Fact]
        public void Serialize_SingleFileNode_IncludesAllFields()
        {
            var graph = new SigningGraph();
            var cert = new SimpleCertificateIdentifier("MyCert");
            var metadata = CreateMetadata("file1.dll");
            var contentKey = new FileContentKey(new ContentHash(ImmutableArray.Create<byte>(1, 2, 3)), "file1.dll");
            var location = new FileLocation("/tmp/file1.dll", RelativePathInContainer: null);
            var node = new FileNode(contentKey, location, metadata, cert);

            graph.AddNode(node, null);
            graph.FinalizeDiscovery();

            // Simulate the node being signed
            node.SigningDetails = new DryRunSigningDetails();

            var json = SigningGraphSerializer.Serialize(graph);
            var doc = JsonDocument.Parse(json);

            var files = doc.RootElement.GetProperty("files");
            Assert.Equal(1, files.GetArrayLength());

            var fileEntry = files[0];
            Assert.Equal("/tmp/file1.dll", fileEntry.GetProperty("path").GetString());
            Assert.Equal("file1.dll", fileEntry.GetProperty("fileName").GetString());
            Assert.Equal("MyCert", fileEntry.GetProperty("certificate").GetString());
            Assert.False(fileEntry.GetProperty("isContainer").GetBoolean());

            // Signing details present
            var details = fileEntry.GetProperty("signingDetails");
            Assert.Equal("DryRun", details.GetProperty("providerName").GetString());

            // Certificate in certificates section
            var certs = doc.RootElement.GetProperty("certificates");
            Assert.True(certs.TryGetProperty("MyCert", out var certDetails));
            Assert.Equal("MyCert", certDetails.GetProperty("name").GetString());
        }

        [Fact]
        public void Serialize_ContainerWithChildren_ShowsRelationships()
        {
            var graph = new SigningGraph();
            var cert = new SimpleCertificateIdentifier("TestCert");
            var metadata = CreateMetadata("container.zip");

            var containerKey = new FileContentKey(new ContentHash(ImmutableArray.Create<byte>(10)), "container.zip");
            var containerLocation = new FileLocation("/tmp/container.zip", RelativePathInContainer: null);
            var containerNode = new FileNode(containerKey, containerLocation, metadata, cert);

            var childMeta = CreateMetadata("inner.dll");
            var childKey = new FileContentKey(new ContentHash(ImmutableArray.Create<byte>(20)), "inner.dll");
            var childLocation = new FileLocation("/tmp/extract/inner.dll", RelativePathInContainer: "inner.dll");
            var childNode = new FileNode(childKey, childLocation, childMeta, cert);

            graph.AddNode(containerNode, null);
            graph.AddNode(childNode, containerNode);
            graph.FinalizeDiscovery();

            var json = SigningGraphSerializer.Serialize(graph);
            var doc = JsonDocument.Parse(json);

            var files = doc.RootElement.GetProperty("files");
            Assert.Equal(2, files.GetArrayLength());

            // Find the container entry
            JsonElement containerEntry = default;
            JsonElement childEntry = default;
            for (int i = 0; i < files.GetArrayLength(); i++)
            {
                var f = files[i];
                if (f.GetProperty("fileName").GetString() == "container.zip")
                    containerEntry = f;
                else
                    childEntry = f;
            }

            // Container should show children
            Assert.True(containerEntry.GetProperty("isContainer").GetBoolean());
            Assert.Equal(1, containerEntry.GetProperty("childCount").GetInt32());
            var children = containerEntry.GetProperty("children");
            Assert.Equal("inner.dll", children[0].GetString());

            // Child should show parent and pathInContainer
            Assert.Equal("/tmp/container.zip", childEntry.GetProperty("parentContainer").GetString());
            Assert.Equal("inner.dll", childEntry.GetProperty("pathInContainer").GetString());
            Assert.False(childEntry.GetProperty("isContainer").GetBoolean());
        }

        [Fact]
        public void Serialize_ReferenceNode_ShowsCanonical()
        {
            var graph = new SigningGraph();
            var cert = new SimpleCertificateIdentifier("SharedCert");
            var metadata = CreateMetadata("shared.dll");
            var contentKey = new FileContentKey(new ContentHash(ImmutableArray.Create<byte>(99)), "shared.dll");

            var canonicalLocation = new FileLocation("/tmp/a/shared.dll", RelativePathInContainer: null);
            var canonicalNode = new FileNode(contentKey, canonicalLocation, metadata, cert);

            var refLocation = new FileLocation("/tmp/b/shared.dll", RelativePathInContainer: null);
            var refNode = new ReferenceNode(contentKey, refLocation, canonicalNode);

            graph.AddNode(canonicalNode, null);
            graph.AddNode(refNode, null);
            graph.FinalizeDiscovery();

            var json = SigningGraphSerializer.Serialize(graph);
            var doc = JsonDocument.Parse(json);

            var files = doc.RootElement.GetProperty("files");
            Assert.Equal(2, files.GetArrayLength());

            // Find the reference node entry
            JsonElement refEntry = default;
            for (int i = 0; i < files.GetArrayLength(); i++)
            {
                var f = files[i];
                if (f.TryGetProperty("isDuplicate", out _))
                    refEntry = f;
            }

            Assert.True(refEntry.GetProperty("isDuplicate").GetBoolean());
            Assert.Equal("/tmp/a/shared.dll", refEntry.GetProperty("canonicalPath").GetString());
        }

        [Fact]
        public void Serialize_MultipleCerts_DeduplicatedInCertsSection()
        {
            var graph = new SigningGraph();
            var cert1 = new SimpleCertificateIdentifier("CertA");
            var cert2 = new SimpleCertificateIdentifier("CertB");

            var node1 = CreateSimpleFileNode("file1.dll", new byte[] { 1 }, "/tmp/file1.dll", cert1);
            var node2 = CreateSimpleFileNode("file2.dll", new byte[] { 2 }, "/tmp/file2.dll", cert1);
            var node3 = CreateSimpleFileNode("file3.dll", new byte[] { 3 }, "/tmp/file3.dll", cert2);

            graph.AddNode(node1, null);
            graph.AddNode(node2, null);
            graph.AddNode(node3, null);
            graph.FinalizeDiscovery();

            var json = SigningGraphSerializer.Serialize(graph);
            var doc = JsonDocument.Parse(json);

            var certs = doc.RootElement.GetProperty("certificates");
            Assert.True(certs.TryGetProperty("CertA", out _));
            Assert.True(certs.TryGetProperty("CertB", out _));

            // Exactly 2 certs despite 3 files
            int certCount = 0;
            foreach (var _ in certs.EnumerateObject()) certCount++;
            Assert.Equal(2, certCount);
        }

        [Fact]
        public void Serialize_NullCertificate_ExcludedFromCertsSection()
        {
            var graph = new SigningGraph();

            // Node with no certificate (e.g. file that doesn't need signing)
            var node = CreateSimpleFileNode("readme.txt", new byte[] { 5 }, "/tmp/readme.txt", certificateId: null);

            graph.AddNode(node, null);
            graph.FinalizeDiscovery();

            var json = SigningGraphSerializer.Serialize(graph);
            var doc = JsonDocument.Parse(json);

            var fileEntry = doc.RootElement.GetProperty("files")[0];
            Assert.False(fileEntry.TryGetProperty("certificate", out _));

            var certs = doc.RootElement.GetProperty("certificates");
            int certCount = 0;
            foreach (var _ in certs.EnumerateObject()) certCount++;
            Assert.Equal(0, certCount);
        }

        [Fact]
        public void Serialize_ESRPCliSigningDetails_IncludesOperationId()
        {
            var graph = new SigningGraph();
            var cert = new SimpleCertificateIdentifier("TestCert");
            var node = CreateSimpleFileNode("app.dll", new byte[] { 7 }, "/tmp/app.dll", cert);

            graph.AddNode(node, null);
            graph.FinalizeDiscovery();

            var opId = System.Guid.NewGuid();
            node.SigningDetails = new ESRPCliSigningDetails("TestCert", opId);

            var json = SigningGraphSerializer.Serialize(graph);
            var doc = JsonDocument.Parse(json);

            var details = doc.RootElement.GetProperty("files")[0].GetProperty("signingDetails");
            Assert.Equal("ESRP CLI", details.GetProperty("providerName").GetString());
            Assert.Equal("TestCert", details.GetProperty("certificateName").GetString());
            Assert.Equal(opId.ToString(), details.GetProperty("operationId").GetString());
        }

        [Fact]
        public void Serialize_ESRPClientExeSigningDetails_IncludesCertName()
        {
            var graph = new SigningGraph();
            var cert = new SimpleCertificateIdentifier("TestCert");
            var node = CreateSimpleFileNode("app.dll", new byte[] { 8 }, "/tmp/app.dll", cert);

            graph.AddNode(node, null);
            graph.FinalizeDiscovery();

            node.SigningDetails = new ESRPClientExeSigningDetails("TestCert");

            var json = SigningGraphSerializer.Serialize(graph);
            var doc = JsonDocument.Parse(json);

            var details = doc.RootElement.GetProperty("files")[0].GetProperty("signingDetails");
            Assert.Equal("ESRPClient.exe", details.GetProperty("providerName").GetString());
            Assert.Equal("TestCert", details.GetProperty("certificateName").GetString());
        }

        [Fact]
        public void Serialize_NoSigningDetails_ExcludesSigningDetailsField()
        {
            var graph = new SigningGraph();
            var cert = new SimpleCertificateIdentifier("TestCert");
            var node = CreateSimpleFileNode("app.dll", new byte[] { 9 }, "/tmp/app.dll", cert);

            graph.AddNode(node, null);
            graph.FinalizeDiscovery();

            // Don't set SigningDetails

            var json = SigningGraphSerializer.Serialize(graph);
            var doc = JsonDocument.Parse(json);

            var fileEntry = doc.RootElement.GetProperty("files")[0];
            Assert.False(fileEntry.TryGetProperty("signingDetails", out _));
        }

        #region Helpers

        private static FileNode CreateSimpleFileNode(string fileName, byte[] hashBytes, string path, ICertificateIdentifier? certificateId)
        {
            var contentKey = new FileContentKey(new ContentHash(ImmutableArray.Create(hashBytes)), fileName);
            var location = new FileLocation(path, RelativePathInContainer: null);
            var metadata = CreateMetadata(fileName);
            return new FileNode(contentKey, location, metadata, certificateId);
        }

        private static IFileMetadata CreateMetadata(string fileName)
        {
            var mock = new Mock<IFileMetadata>();
            mock.Setup(m => m.FileName).Returns(fileName);
            mock.Setup(m => m.ExecutableType).Returns(ExecutableType.None);
            mock.Setup(m => m.TargetFramework).Returns((string?)null);
            return mock.Object;
        }

        /// <summary>
        /// Simple certificate identifier for testing.
        /// </summary>
        internal class SimpleCertificateIdentifier : ICertificateIdentifier
        {
            public string Name { get; }
            public bool AlwaysSign => false;

            public SimpleCertificateIdentifier(string name)
            {
                Name = name;
            }

            public IDictionary<string, object?> SerializeDetails() =>
                new Dictionary<string, object?> { ["name"] = Name };
        }

        #endregion
    }
}
