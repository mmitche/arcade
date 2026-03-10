// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.DotNet.RecursiveSigning.Abstractions;
using Microsoft.DotNet.RecursiveSigning.Models;

namespace Microsoft.DotNet.RecursiveSigning.Implementation
{
    /// <summary>
    /// Signing provider that invokes the ESRP CLI tool using regularSigning mode.
    /// Groups files by certificate and submits all certificate groups in parallel,
    /// each as a separate CLI invocation.
    /// </summary>
    public sealed class ESRPCliSigningProvider : ESRPSigningProviderBase
    {
        private readonly ESRPCliSigningConfiguration _configuration;

        public ESRPCliSigningProvider(
            ESRPCliSigningConfiguration configuration,
            IProcessRunner processRunner,
            ILogger<ESRPCliSigningProvider> logger)
            : base(processRunner, logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        protected override ESRPSigningConfiguration Configuration => _configuration;
        protected override string ProviderName => "ESRP CLI";

        protected override async Task<bool> ExecuteSigningAsync(
            Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)> groups,
            IReadOnlyList<(FileNode node, string outputPath)> allFiles,
            CancellationToken cancellationToken)
        {
            // Submit all cert groups in parallel
            var tasks = groups.Select(g =>
                SignCertGroupAsync(g.Key, g.Value.cert, g.Value.files, cancellationToken));
            var results = await Task.WhenAll(tasks);

            if (results.All(r => r))
            {
                Logger.LogInformation("ESRP CLI signing succeeded for all {Count} file(s)", allFiles.Count);
                return true;
            }

            return false;
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Per-cert-group signing
        // ────────────────────────────────────────────────────────────────────────

        private async Task<bool> SignCertGroupAsync(
            string certName,
            ESRPCertificateIdentifier cert,
            List<(FileNode node, string outputPath)> groupFiles,
            CancellationToken cancellationToken)
        {
            var workDir = Path.Combine(_configuration.TempDirectory, Guid.NewGuid().ToString());
            Directory.CreateDirectory(workDir);

            try
            {
                var rootDir = RootInputOutputPathHelper.GetCommonRootForFiles(
                    groupFiles.Select(f => f.node.Location.FilePathOnDisk!).ToList());

                // ESRP CLI expects forward-slash paths
                var normalizedRoot = NormalizePath(rootDir);

                // Write the operations JSON and pattern file for this cert group
                var operationsJson = BuildOperationsJson(cert);
                File.WriteAllText(Path.Combine(workDir, "inlineOperations.json"), operationsJson);

                var patternContent = BuildPatternFileContent(groupFiles, normalizedRoot);
                File.WriteAllText(Path.Combine(workDir, "pattern.txt"), patternContent);

                var arguments = BuildArguments(workDir, normalizedRoot);

                Logger.LogInformation("Signing {Count} file(s) with certificate '{Cert}'",
                    groupFiles.Count, certName);
                LogVerbose("ESRP CLI operations JSON:\n{Json}", operationsJson);
                LogVerbose("ESRP CLI pattern file:\n{Pattern}", patternContent);
                LogVerbose("ESRP CLI arguments: dotnet {Args}", RedactAuthArguments(arguments));

                var result = await ProcessRunner.RunAsync("dotnet", arguments, cancellationToken);

                LogVerbose("ESRP CLI stdout:\n{Stdout}", result.StandardOutput);
                if (!string.IsNullOrWhiteSpace(result.StandardError))
                {
                    LogVerbose("ESRP CLI stderr:\n{Stderr}", result.StandardError);
                }

                // Always write logs to files for post-mortem diagnostics
                var safeCertName = string.Join("_", certName.Split(Path.GetInvalidFileNameChars()));
                WriteInvocationLog(
                    $"ESRP CLI Invocation: {certName}",
                    $"esrp-{safeCertName}",
                    result,
                    $"dotnet {RedactAuthArguments(arguments)}");

                var parsed = ESRPCliResultParser.Parse(
                    result.ExitCode, result.StandardOutput, result.StandardError);

                if (parsed.OperationId.HasValue)
                {
                    Logger.LogInformation("ESRP operation ID: {OperationId}", parsed.OperationId.Value);
                }

                if (!parsed.Success)
                {
                    Logger.LogError("ESRP CLI signing failed for '{Cert}': {Error}",
                        certName, parsed.ErrorMessage);

                    // Surface individual failure details at error level so they appear
                    // in the build log even in non-verbose mode
                    foreach (var detail in parsed.FailureDetails)
                    {
                        Logger.LogError("  {FailureDetail}", detail);
                    }

                    return false;
                }

                // Attach provider-specific signing details to each node
                var signingDetails = new ESRPCliSigningDetails(certName, parsed.OperationId);
                foreach (var (node, _) in groupFiles)
                {
                    node.SigningDetails = signingDetails;
                }

                return true;
            }
            finally
            {
                TryDeleteDirectory(workDir);
            }
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Operations & pattern file
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Builds the inline operations JSON for a certificate, written to
        /// inlineOperations.json and passed via the <c>-j</c> flag.
        /// </summary>
        internal string BuildOperationsJson(ESRPCertificateIdentifier cert)
        {
            var operations = ExtractOperations(cert.CertificateDefinition);
            return JsonSerializer.Serialize(operations, PrettyJsonOptions);
        }

        /// <summary>
        /// Builds a comma-separated pattern file of relative paths.
        /// </summary>
        internal static string BuildPatternFileContent(
            IReadOnlyList<(FileNode node, string outputPath)> files,
            string rootDir)
        {
            return string.Join(',',
                files.Select(f => GetRelativePath(f.node.Location.FilePathOnDisk!, rootDir)));
        }

        // ────────────────────────────────────────────────────────────────────────
        //  CLI argument construction
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Builds CLI arguments for the ESRP CLI regularSigning mode.
        /// </summary>
        internal string BuildArguments(string workDir, string rootDir)
        {
            var sb = new StringBuilder();

            // Core signing flags
            sb.Append($"--roll-forward Major {_configuration.ESRPCliPath} vsts.sign");
            sb.Append(" -x regularSigning");
            sb.Append(" -y \"inlineSignParams\"");
            sb.Append(" -c 400");
            sb.Append($" -j \"{Path.Combine(workDir, "inlineOperations.json")}\"");
            sb.Append(" -u false");
            sb.Append($" -f \"{rootDir}\"");
            sb.Append($" -p \"{Path.Combine(workDir, "pattern.txt")}\"");
            sb.Append($" -m {_configuration.BatchSize}");
            sb.Append($" -t {_configuration.TimeoutInMinutes}");
            sb.Append(" -v \"Tls12\"");

            // Service endpoint
            sb.Append($" -s \"{_configuration.GatewayUrl}\"");
            sb.Append($" -o \"{_configuration.Organization}\"");
            sb.Append($" -i \"{_configuration.OrganizationInfoUrl}\"");
            sb.Append(" -r true");
            sb.Append(" -skipAdoReportAttachment false");
            sb.Append(" -pendingAnalysisWaitTimeoutMinutes 5");
            sb.Append($" -resourceUri {_configuration.ResourceUri}");

            // Identity
            sb.Append($" -esrpClientId {_configuration.EsrpClientId}");
            sb.Append($" -a {_configuration.ClientId}");
            sb.Append($" -d {_configuration.TenantId}");
            sb.Append($" -z {SerializeJsonArg(new { akv = _configuration.KeyVaultName, cert = _configuration.CertificateName })}");

            // Authentication
            AppendAuthArguments(sb);

            return sb.ToString();
        }

        private void AppendAuthArguments(StringBuilder sb)
        {
            if (_configuration.AuthMode == ESRPAuthMode.FederatedToken)
            {
                sb.Append(" -useMSIAuthentication true");
                var tokenData = BuildFederatedTokenData();
                sb.Append($" -federatedTokenData {SerializeJsonArg(tokenData)}");
            }
            else
            {
                sb.Append(" -useMSIAuthentication false");
                sb.Append($" -encryptedCertificateData {SerializeJsonArg(new { authCert = _configuration.EncryptedAuthCertPath, encryptionKey = _configuration.EncryptionKeyPath })}");
            }
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Authentication
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Builds the federated token data for ESRP federated auth. Encrypts the system access
        /// token with AES and writes the key/IV and ciphertext to temp files,
        /// matching the Sign repo's ESRPCliDll approach.
        /// </summary>
        private object BuildFederatedTokenData()
        {
            var accessToken = Environment.GetEnvironmentVariable(_configuration.SystemAccessTokenEnvVar);
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new InvalidOperationException(
                    $"Environment variable '{_configuration.SystemAccessTokenEnvVar}' is not set. " +
                    "Required for FederatedToken auth mode.");
            }

            var (encryptionKeyPath, encryptedTokenPath) = EncryptAccessToken(accessToken.Trim());

            return new
            {
                jobId = GetEnv("SYSTEM_JOBID"),
                planId = GetEnv("SYSTEM_PLANID"),
                projectId = GetEnv("SYSTEM_TEAMPROJECTID"),
                hub = GetEnv("SYSTEM_HOSTTYPE"),
                uri = Environment.GetEnvironmentVariable("SYSTEM_COLLECTIONURI")
                    ?? GetEnv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"),
                managedIdentityId = _configuration.ClientId,
                managedIdentityTenantId = _configuration.TenantId,
                serviceConnectionId = _configuration.ServiceConnectionId,
                tempDirectory = Environment.GetEnvironmentVariable("AGENT_TEMPDIRECTORY")
                    ?? _configuration.TempDirectory,
                encryptionKey = encryptionKeyPath,
                systemAccessToken = encryptedTokenPath,
            };

            static string GetEnv(string name) =>
                Environment.GetEnvironmentVariable(name) ?? "";
        }

        /// <summary>
        /// AES-CBC encrypts the access token and writes the key/IV and ciphertext to disk.
        /// Returns the paths to the key file and encrypted token file.
        /// </summary>
        private (string keyPath, string tokenPath) EncryptAccessToken(string accessToken)
        {
            var tempDir = _configuration.TempDirectory;
            Directory.CreateDirectory(tempDir);
            var keyPath = Path.Combine(tempDir, "esrp-encryption-key.json");
            var tokenPath = Path.Combine(tempDir, "esrp-encrypted-token.txt");

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateKey();
            aes.GenerateIV();

            File.WriteAllText(keyPath, JsonSerializer.Serialize(
                new
                {
                    key = ToHex(aes.Key),
                    iv = ToHex(aes.IV),
                },
                CompactJsonOptions));

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            var plaintext = Encoding.UTF8.GetBytes(accessToken);
            var ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
            File.WriteAllText(tokenPath, ToHex(ciphertext));

            return (keyPath, tokenPath);

            static string ToHex(byte[] bytes) =>
                BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Path utilities
        // ────────────────────────────────────────────────────────────────────────

        private static string GetRelativePath(string filePath, string rootDir)
        {
            var normalized = NormalizePath(filePath);
            if (!normalized.StartsWith(rootDir, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"File path '{filePath}' is not under root directory '{rootDir}'.");
            }

            return normalized[(rootDir.Length + 1)..]; // skip the trailing '/'
        }

        internal static string NormalizePath(string path) =>
            Path.GetFullPath(path).Replace('\\', '/').TrimEnd('/');

        // ────────────────────────────────────────────────────────────────────────
        //  JSON / logging helpers
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Serializes an object to a JSON string wrapped in outer quotes with escaped
        /// inner quotes, suitable for passing as a CLI argument on Windows.
        /// Matches Newtonsoft's <c>JsonConvert.ToString(JsonConvert.SerializeObject(obj))</c>.
        /// </summary>
        private static string SerializeJsonArg(object value)
        {
            var json = JsonSerializer.Serialize(value, CompactJsonOptions);
            return "\"" + json.Replace("\"", "\\\"") + "\"";
        }

        private static string RedactAuthArguments(string arguments)
        {
            var redacted = arguments;
            foreach (var flag in new[] { "-federatedTokenData", "-encryptedCertificateData" })
            {
                var idx = redacted.IndexOf(flag, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) continue;
                var endIdx = redacted.IndexOf(" -", idx + flag.Length);
                if (endIdx < 0) endIdx = redacted.Length;
                redacted = redacted[..(idx + flag.Length)] + " [REDACTED]" + redacted[endIdx..];
            }
            return redacted;
        }

        protected override void LogDryRun(
            Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)> groups)
        {
            Logger.LogInformation("=== ESRP CLI Dry Run ({Count} certificate group(s)) ===", groups.Count);
            foreach (var (certName, (cert, groupFiles)) in groups)
            {
                Logger.LogInformation("  Certificate '{Cert}': {Count} file(s)", certName, groupFiles.Count);
                Logger.LogInformation("  Operations:\n{Ops}", BuildOperationsJson(cert));
                foreach (var (node, _) in groupFiles)
                {
                    Logger.LogInformation("    {File}", node.Location.FilePathOnDisk);
                }
            }
            Logger.LogInformation("=== End Dry Run ===");
        }
    }
}
