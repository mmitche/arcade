// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Microsoft.DotNet.RecursiveSigning.Abstractions;
using Microsoft.DotNet.RecursiveSigning.Implementation;
using Microsoft.DotNet.RecursiveSigning.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Microsoft.DotNet.RecursiveSigning.Tests
{
    public class ESRPClientExeSigningProviderTests
    {
        private static readonly string RootDir = OperatingSystem.IsWindows() ? @"C:\build" : "/build";

        private static ESRPClientExeSigningConfiguration CreateConfig(bool dryRun = false) => new()
        {
            ESRPClientExePath = @"C:\tools\EsrpClient.exe",
            EsrpClientId = "test-esrp-client-id",
            ClientId = "test-client-id",
            TenantId = "test-tenant-id",
            TimeoutInMinutes = 30,
            MaxDegreeOfParallelism = 4,
            TempDirectory = OperatingSystem.IsWindows() ? @"C:\temp" : "/tmp",
            DryRun = dryRun,
        };

        private static ESRPCertificateIdentifier CreateCert(string name, string keyCode = "CP-230012")
        {
            var opsJson = "[{\"KeyCode\":\"" + keyCode + "\",\"OperationCode\":\"SigntoolSign\",\"Parameters\":{\"OpusName\":\"Microsoft\"},\"ToolName\":\"sign\",\"ToolVersion\":\"1.0\"}]";
            var ops = JsonDocument.Parse(opsJson).RootElement;
            return new ESRPCertificateIdentifier(name, ops);
        }

        private static FileNode CreateFileNode(string relativePath, ESRPCertificateIdentifier cert)
        {
            var fullPath = (RootDir + "/" + relativePath).Replace('/', System.IO.Path.DirectorySeparatorChar);
            var contentKey = new FileContentKey(
                new ContentHash(ImmutableArray.Create<byte>(1, 2, 3, 4)),
                System.IO.Path.GetFileName(relativePath));
            var location = new FileLocation(fullPath, null);
            var metadata = new FileMetadata(System.IO.Path.GetFileName(relativePath));
            return new FileNode(contentKey, location, metadata, cert);
        }

        [Fact]
        public void GroupFilesByCertificate_SingleCert_ProducesSingleGroup()
        {
            var cert = CreateCert("CertA");
            var files = new List<(FileNode, string)>
            {
                (CreateFileNode("bin/a.dll", cert), RootDir + "/bin/a.dll"),
                (CreateFileNode("bin/b.dll", cert), RootDir + "/bin/b.dll"),
            };

            var groups = ESRPClientExeSigningProvider.GroupFilesByCertificate(files);

            groups.Should().HaveCount(1);
            groups["CertA"].files.Should().HaveCount(2);
        }

        [Fact]
        public void GroupFilesByCertificate_MultipleCerts_ProducesMultipleGroups()
        {
            var certA = CreateCert("CertA", "CP-111");
            var certB = CreateCert("CertB", "CP-222");
            var files = new List<(FileNode, string)>
            {
                (CreateFileNode("bin/a.dll", certA), RootDir + "/bin/a.dll"),
                (CreateFileNode("bin/b.exe", certB), RootDir + "/bin/b.exe"),
                (CreateFileNode("bin/c.dll", certA), RootDir + "/bin/c.dll"),
            };

            var groups = ESRPClientExeSigningProvider.GroupFilesByCertificate(files);

            groups.Should().HaveCount(2);
            groups["CertA"].files.Should().HaveCount(2);
            groups["CertB"].files.Should().HaveCount(1);
        }

        [Fact]
        public void BuildSubmissionJson_ContainsSignBatchesAndOperations()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);
            var cert = CreateCert("CertA", "CP-230012");
            var files = new List<(FileNode, string)>
            {
                (CreateFileNode("bin/a.dll", cert), RootDir + "\\bin\\a.dll"),
            };

            var groups = ESRPClientExeSigningProvider.GroupFilesByCertificate(files);
            var json = provider.BuildSubmissionJson(groups);
            var doc = JsonDocument.Parse(json);

            doc.RootElement.GetProperty("Version").GetString().Should().Be("1.0.0");
            doc.RootElement.GetProperty("SignBatches").GetArrayLength().Should().Be(1);

            var batch = doc.RootElement.GetProperty("SignBatches")[0];
            batch.GetProperty("SourceLocationType").GetString().Should().Be("UNC");
            batch.GetProperty("DestinationLocationType").GetString().Should().Be("UNC");
            batch.GetProperty("SignRequestFiles").GetArrayLength().Should().Be(1);
            batch.GetProperty("SigningInfo").GetProperty("Operations")[0]
                .GetProperty("KeyCode").GetString().Should().Be("CP-230012");
        }

        [Fact]
        public void BuildSubmissionJson_MultipleCerts_ProducesMultipleSignBatches()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);
            var certA = CreateCert("CertA", "CP-111");
            var certB = CreateCert("CertB", "CP-222");
            var files = new List<(FileNode, string)>
            {
                (CreateFileNode("bin/a.dll", certA), RootDir + "\\bin\\a.dll"),
                (CreateFileNode("bin/b.exe", certB), RootDir + "\\bin\\b.exe"),
            };

            var groups = ESRPClientExeSigningProvider.GroupFilesByCertificate(files);
            var json = provider.BuildSubmissionJson(groups);
            var doc = JsonDocument.Parse(json);

            doc.RootElement.GetProperty("SignBatches").GetArrayLength().Should().Be(2);
        }

        [Fact]
        public void BuildAuthJson_WithExplicitParams_ReturnsAuthJson()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var authJson = provider.BuildAuthJson();

            authJson.Should().NotBeNull();
            var doc = JsonDocument.Parse(authJson!);
            doc.RootElement.GetProperty("Version").GetString().Should().Be("1.0.0");
            doc.RootElement.GetProperty("ClientId").GetString().Should().Be("test-client-id");
            doc.RootElement.GetProperty("TenantId").GetString().Should().Be("test-tenant-id");
            doc.RootElement.GetProperty("AuthenticationType").GetString().Should().Be("AAD_CERT");
        }

        [Fact]
        public void BuildAuthJson_WithExplicitParams_IncludesAuthCertAndRequestSigningCert()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var authJson = provider.BuildAuthJson();

            authJson.Should().NotBeNull();
            var doc = JsonDocument.Parse(authJson!);
            doc.RootElement.GetProperty("AuthCert").GetProperty("SubjectName").GetString().Should().Be("test-client-id.microsoft.com");
            doc.RootElement.GetProperty("AuthCert").GetProperty("SendX5c").GetBoolean().Should().BeTrue();
            doc.RootElement.GetProperty("RequestSigningCert").GetProperty("SubjectName").GetString().Should().Be("test-esrp-client-id");
            doc.RootElement.GetProperty("RequestSigningCert").GetProperty("SendX5c").GetBoolean().Should().BeFalse();
        }

        [Fact]
        public void BuildAuthJson_WithoutParams_UsesEnvVar()
        {
            var config = new ESRPClientExeSigningConfiguration
            {
                ESRPClientExePath = @"C:\tools\EsrpClient.exe",
                TempDirectory = OperatingSystem.IsWindows() ? @"C:\temp" : "/tmp",
            };
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var prevValue = Environment.GetEnvironmentVariable(ESRPClientExeSigningProvider.AuthConfigEnvVar);
            try
            {
                Environment.SetEnvironmentVariable(ESRPClientExeSigningProvider.AuthConfigEnvVar, "{\"Version\":\"1.0.0\",\"test\":true}");
                var authJson = provider.BuildAuthJson();

                authJson.Should().Contain("\"test\":true");
            }
            finally
            {
                Environment.SetEnvironmentVariable(ESRPClientExeSigningProvider.AuthConfigEnvVar, prevValue);
            }
        }

        [Fact]
        public void BuildConfigJson_ContainsExpectedFields()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var json = provider.BuildConfigJson();
            json.Should().NotBeNull();
            var doc = JsonDocument.Parse(json!);

            doc.RootElement.GetProperty("Version").GetString().Should().Be("1.0.0");
            doc.RootElement.GetProperty("EsrpSessionTimeoutInSec").GetInt32().Should().Be(1500); // (30-5)*60
            doc.RootElement.GetProperty("MaxDegreeOfParallelism").GetInt32().Should().Be(4);
        }

        [Fact]
        public void BuildConfigJson_ReturnsNull_WhenSessionConfigEnvVarSet()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var prev = Environment.GetEnvironmentVariable(ESRPClientExeSigningProvider.SessionConfigEnvVar);
            try
            {
                Environment.SetEnvironmentVariable(ESRPClientExeSigningProvider.SessionConfigEnvVar, "{\"Version\":\"1.0.0\"}");
                var json = provider.BuildConfigJson();
                json.Should().BeNull();
            }
            finally
            {
                Environment.SetEnvironmentVariable(ESRPClientExeSigningProvider.SessionConfigEnvVar, prev);
            }
        }

        [Fact]
        public void BuildArguments_ContainsExpectedFlags()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var args = provider.BuildArguments(
                @"C:\temp\submission.json",
                "{\"Version\":\"1.0.0\"}",
                "{\"Version\":\"1.0.0\"}",
                "{\"Version\":\"1.0.0\"}",
                @"C:\temp\output.json",
                @"C:\temp\output.txt");

            args.Should().Contain("Sign");
            args.Should().Contain("-i");
            args.Should().Contain("-a");
            args.Should().Contain("-c");
            args.Should().Contain("-p");
            args.Should().Contain("-o");
            args.Should().Contain("-l Verbose");
            args.Should().Contain("-f");
        }

        [Fact]
        public void BuildArguments_WithNullAuth_OmitsAuthFlag()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var args = provider.BuildArguments(
                @"C:\temp\submission.json",
                null,
                "{\"Version\":\"1.0.0\"}",
                "{\"Version\":\"1.0.0\"}",
                @"C:\temp\output.json",
                @"C:\temp\output.txt");

            args.Should().NotContain(" -a ");
        }

        [Fact]
        public void BuildArguments_WithNullConfig_OmitsConfigFlag()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var args = provider.BuildArguments(
                @"C:\temp\submission.json",
                "{\"Version\":\"1.0.0\"}",
                null,
                "{\"Version\":\"1.0.0\"}",
                @"C:\temp\output.json",
                @"C:\temp\output.txt");

            args.Should().NotContain(" -c ");
        }

        [Fact]
        public void BuildArguments_WithNullPolicy_OmitsPolicyFlag()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var args = provider.BuildArguments(
                @"C:\temp\submission.json",
                "{\"Version\":\"1.0.0\"}",
                "{\"Version\":\"1.0.0\"}",
                null,
                @"C:\temp\output.json",
                @"C:\temp\output.txt");

            args.Should().NotContain(" -p ");
        }

        [Fact]
        public void BuildPolicyJson_ReturnsDefault_WhenEnvVarNotSet()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var prev = Environment.GetEnvironmentVariable(ESRPClientExeSigningProvider.PolicyConfigEnvVar);
            try
            {
                Environment.SetEnvironmentVariable(ESRPClientExeSigningProvider.PolicyConfigEnvVar, null);
                var json = provider.BuildPolicyJson();
                json.Should().NotBeNull();
                var doc = JsonDocument.Parse(json!);
                doc.RootElement.GetProperty("Version").GetString().Should().Be("1.0.0");
            }
            finally
            {
                Environment.SetEnvironmentVariable(ESRPClientExeSigningProvider.PolicyConfigEnvVar, prev);
            }
        }

        [Fact]
        public void BuildPolicyJson_ReturnsNull_WhenEnvVarSet()
        {
            var config = CreateConfig();
            var provider = new ESRPClientExeSigningProvider(config, new FakeProcessRunner(), NullLogger<ESRPClientExeSigningProvider>.Instance);

            var prev = Environment.GetEnvironmentVariable(ESRPClientExeSigningProvider.PolicyConfigEnvVar);
            try
            {
                Environment.SetEnvironmentVariable(ESRPClientExeSigningProvider.PolicyConfigEnvVar, "{\"Version\":\"1.0.0\"}");
                var json = provider.BuildPolicyJson();
                json.Should().BeNull();
            }
            finally
            {
                Environment.SetEnvironmentVariable(ESRPClientExeSigningProvider.PolicyConfigEnvVar, prev);
            }
        }

        [Fact]
        public void EscapeJsonArg_EscapesQuotes()
        {
            var input = "{\"key\":\"value\"}";
            var escaped = ESRPClientExeSigningProvider.EscapeJsonArg(input);
            escaped.Should().Be("{\\\"key\\\":\\\"value\\\"}");
        }

        [Fact]
        public void ParseResult_ExitCodeZero_ReturnsSuccess()
        {
            var result = ESRPClientExeSigningProvider.ParseResult(0, "", "", "", "");
            result.Success.Should().BeTrue();
        }

        [Fact]
        public void ParseResult_NonZeroExitCode_ReturnsFailure()
        {
            var result = ESRPClientExeSigningProvider.ParseResult(1, "", "some error", "", "");
            result.Success.Should().BeFalse();
            result.ErrorMessage.Should().Contain("exited with code 1");
            result.ErrorMessage.Should().Contain("some error");
        }

        [Fact]
        public void ParseResult_OAuthFailure_ReturnsFailure()
        {
            var result = ESRPClientExeSigningProvider.ParseResult(0, "", "", "", "Something Invalid OAUTH token. happened");
            result.Success.Should().BeFalse();
            result.ErrorMessage.Should().Contain("OAUTH");
        }

        [Fact]
        public void ParseResult_OutputJsonWithFailStatus_ReturnsFailure()
        {
            var outputJson = """
            {
                "SubmissionResponses": [
                    {
                        "CustomerCorrelationId": "abc-123",
                        "StatusCode": "FailDoNotRetry",
                        "ErrorInfo": {"Details": {"error": "something went wrong"}}
                    }
                ]
            }
            """;
            var result = ESRPClientExeSigningProvider.ParseResult(0, "", "", outputJson, "");
            result.Success.Should().BeFalse();
            result.ErrorMessage.Should().Contain("FailDoNotRetry");
        }

        [Fact]
        public async Task SignFilesAsync_DryRun_ReturnsTrue_DoesNotInvokeProcess()
        {
            var config = CreateConfig(dryRun: true);
            var processRunner = new FakeProcessRunner();
            var provider = new ESRPClientExeSigningProvider(config, processRunner, NullLogger<ESRPClientExeSigningProvider>.Instance);
            var cert = CreateCert("CertA");
            var files = new List<(FileNode, string)>
            {
                (CreateFileNode("bin/a.dll", cert), RootDir + "/bin/a.dll"),
            };

            var result = await provider.SignFilesAsync(files);

            result.Should().BeTrue();
            processRunner.Invocations.Should().BeEmpty();
        }

        [Fact]
        public async Task SignFilesAsync_EmptyFiles_ReturnsTrue()
        {
            var config = CreateConfig();
            var processRunner = new FakeProcessRunner();
            var provider = new ESRPClientExeSigningProvider(config, processRunner, NullLogger<ESRPClientExeSigningProvider>.Instance);

            var result = await provider.SignFilesAsync(new List<(FileNode, string)>());

            result.Should().BeTrue();
            processRunner.Invocations.Should().BeEmpty();
        }

        [Fact]
        public async Task SignFilesAsync_SingleInvocation_ForAllCertGroups()
        {
            var config = CreateConfig();
            var processRunner = new FakeProcessRunner();
            var provider = new ESRPClientExeSigningProvider(config, processRunner, NullLogger<ESRPClientExeSigningProvider>.Instance);
            var certA = CreateCert("CertA", "CP-111");
            var certB = CreateCert("CertB", "CP-222");
            var files = new List<(FileNode, string)>
            {
                (CreateFileNode("bin/a.dll", certA), RootDir + "/bin/a.dll"),
                (CreateFileNode("bin/b.exe", certB), RootDir + "/bin/b.exe"),
            };

            var result = await provider.SignFilesAsync(files);

            result.Should().BeTrue();
            // ESRPClient.exe uses a single invocation with all SignBatches
            processRunner.Invocations.Should().HaveCount(1);
            processRunner.Invocations[0].FileName.Should().Contain("EsrpClient.exe");
        }

        /// <summary>
        /// Fake process runner that records invocations without running any real process.
        /// Thread-safe for parallel invocation testing.
        /// </summary>
        private sealed class FakeProcessRunner : IProcessRunner
        {
            private readonly List<(string FileName, string Arguments)> _invocations = new();

            public IReadOnlyList<(string FileName, string Arguments)> Invocations
            {
                get { lock (_invocations) { return _invocations.ToList(); } }
            }

            public ProcessResult NextResult { get; set; } = new ProcessResult(0, "", "");

            public Task<ProcessResult> RunAsync(string fileName, string arguments, CancellationToken cancellationToken)
            {
                lock (_invocations)
                {
                    _invocations.Add((fileName, arguments));
                }
                return Task.FromResult(NextResult);
            }
        }
    }
}
