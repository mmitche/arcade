// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.DotNet.RecursiveSigning.Abstractions;
using Microsoft.DotNet.RecursiveSigning.Models;

namespace Microsoft.DotNet.RecursiveSigning.Implementation
{
    /// <summary>
    /// Signing provider that invokes ESRPClient.exe using the Sign command.
    /// Builds a full submission JSON with SignBatches (one per certificate) and submits
    /// all files in a single ESRPClient.exe invocation.
    /// </summary>
    public sealed class ESRPClientExeSigningProvider : ISigningProvider
    {
        private readonly ESRPClientExeSigningConfiguration _configuration;
        private readonly IProcessRunner _processRunner;
        private readonly ILogger<ESRPClientExeSigningProvider> _logger;

        private static readonly JsonSerializerOptions s_prettyJsonOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        private static readonly JsonSerializerOptions s_compactJsonOptions = new();

        /// <summary>
        /// Environment variable name that ESRPClient.exe reads for auth configuration.
        /// When this is set, explicit auth parameters are not required.
        /// </summary>
        internal const string AuthConfigEnvVar = "ESRP_AUTH_CONFIG";

        public ESRPClientExeSigningProvider(
            ESRPClientExeSigningConfiguration configuration,
            IProcessRunner processRunner,
            ILogger<ESRPClientExeSigningProvider> logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<bool> SignFilesAsync(
            IReadOnlyList<(FileNode node, string outputPath)> files,
            CancellationToken cancellationToken = default)
        {
            if (files == null || files.Count == 0)
            {
                return true;
            }

            var groups = GroupFilesByCertificate(files);

            if (_configuration.DryRun)
            {
                LogDryRun(groups);
                return true;
            }

            _logger.LogInformation("Signing {Count} file(s) across {Groups} certificate group(s) via ESRPClient.exe",
                files.Count, groups.Count);

            var workDir = Path.Combine(_configuration.TempDirectory, Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(workDir);

            try
            {
                // Build the submission JSON with all cert groups as SignBatches
                var submissionJson = BuildSubmissionJson(groups);
                var submissionFile = Path.Combine(workDir, "submission.json");
                File.WriteAllText(submissionFile, submissionJson);

                // Build config and policy JSON
                var configJson = BuildConfigJson();
                var policyJson = BuildPolicyJson();

                // Build auth JSON (optional - from params or ESRP_AUTH_CONFIG env var)
                var authJson = BuildAuthJson();

                var outputJsonFile = Path.Combine(workDir, "output.json");
                var outputTxtFile = Path.Combine(workDir, "output.txt");

                var arguments = BuildArguments(submissionFile, authJson, configJson, policyJson, outputJsonFile, outputTxtFile);

                LogVerbose("ESRPClient.exe submission JSON:\n{Json}", submissionJson);
                LogVerbose("ESRPClient.exe arguments: {Args}", RedactAuthArguments(arguments));

                var result = await _processRunner.RunAsync(
                    _configuration.ESRPClientExePath, arguments, cancellationToken);

                LogVerbose("ESRPClient.exe stdout:\n{Stdout}", result.StandardOutput);
                if (!string.IsNullOrWhiteSpace(result.StandardError))
                {
                    LogVerbose("ESRPClient.exe stderr:\n{Stderr}", result.StandardError);
                }

                // Write invocation log
                WriteInvocationLog(result, arguments);

                // Parse output
                var outputJson = File.Exists(outputJsonFile) ? File.ReadAllText(outputJsonFile) : "";
                var outputTxt = File.Exists(outputTxtFile) ? File.ReadAllText(outputTxtFile) : "";

                var parsed = ParseResult(result.ExitCode, result.StandardOutput, result.StandardError, outputJson, outputTxt);

                if (!parsed.Success)
                {
                    _logger.LogError("ESRPClient.exe signing failed: {Error}", parsed.ErrorMessage);
                    return false;
                }

                _logger.LogInformation("ESRPClient.exe signing succeeded for all {Count} file(s)", files.Count);
                return true;
            }
            finally
            {
                TryDeleteDirectory(workDir);
            }
        }

        // ────────────────────────────────────────────────────────────────────────
        //  File grouping
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Groups files by their certificate identifier's friendly name.
        /// </summary>
        internal static Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)>
            GroupFilesByCertificate(IReadOnlyList<(FileNode node, string outputPath)> files)
        {
            var groups = new Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var entry in files)
            {
                var certId = entry.node.CertificateIdentifier as ESRPCertificateIdentifier
                    ?? throw new InvalidOperationException(
                        $"File '{entry.node.Location.FilePathOnDisk}' does not have an ESRPCertificateIdentifier.");

                if (!groups.TryGetValue(certId.FriendlyName, out var group))
                {
                    group = (certId, new List<(FileNode, string)>());
                    groups[certId.FriendlyName] = group;
                }

                group.files.Add(entry);
            }

            return groups;
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Submission JSON
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Builds the full submission JSON with one SignBatch per certificate group.
        /// </summary>
        internal string BuildSubmissionJson(
            Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)> groups)
        {
            var signBatches = new List<object>();

            foreach (var (certName, (cert, groupFiles)) in groups)
            {
                var operations = ESRPCliSigningProvider.ExtractOperations(cert.CertificateDefinition);

                var signRequestFiles = groupFiles.Select(f => new
                {
                    SourceLocation = f.node.Location.FilePathOnDisk!.Replace('/', '\\'),
                    DestinationLocation = f.outputPath.Replace('/', '\\'),
                    CustomerCorrelationId = Guid.NewGuid().ToString(),
                }).ToArray();

                signBatches.Add(new
                {
                    SourceLocationType = "UNC",
                    DestinationLocationType = "UNC",
                    SignRequestFiles = signRequestFiles,
                    SigningInfo = new
                    {
                        Operations = operations,
                    },
                });
            }

            var submission = new
            {
                Version = "1.0.0",
                ContextData = new Dictionary<string, string>
                {
                    ["RecursiveSigning"] = "Sign",
                },
                SignBatches = signBatches,
            };

            return JsonSerializer.Serialize(submission, s_prettyJsonOptions);
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Auth / Config / Policy JSON
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Builds auth JSON from configuration parameters, or reads from the
        /// <c>ESRP_AUTH_CONFIG</c> environment variable.
        /// Returns null if auth should be handled by the environment.
        /// </summary>
        internal string? BuildAuthJson()
        {
            if (_configuration.AuthMode == ESRPAuthMode.FederatedToken)
            {
                return BuildFederatedTokenAuthJson();
            }

            // If explicit auth params are provided, build cert-based auth JSON
            if (!string.IsNullOrEmpty(_configuration.ClientId) &&
                !string.IsNullOrEmpty(_configuration.TenantId))
            {
                var auth = new
                {
                    Version = "1.0.0",
                    ClientId = _configuration.ClientId,
                    EsrpClientId = _configuration.EsrpClientId ?? _configuration.ClientId,
                    TenantId = _configuration.TenantId,
                    AuthenticationType = "AAD_CERT",
                    RequestSigningCert = new
                    {
                        SubjectName = _configuration.EsrpClientId ?? _configuration.ClientId,
                        StoreLocation = "LocalMachine",
                        StoreName = "My",
                        SendX5c = false,
                    },
                };
                return JsonSerializer.Serialize(auth, s_compactJsonOptions);
            }

            // Check ESRP_AUTH_CONFIG environment variable
            var envAuthConfig = Environment.GetEnvironmentVariable(AuthConfigEnvVar);
            if (!string.IsNullOrEmpty(envAuthConfig))
            {
                _logger.LogInformation("Using auth configuration from {EnvVar} environment variable", AuthConfigEnvVar);
                return envAuthConfig;
            }

            if (!_configuration.DryRun)
            {
                throw new InvalidOperationException(
                    $"No auth configuration provided. Supply --federated-token with service connection params, " +
                    $"or --esrp-client-id/--esrp-app-registration/--esrp-tenant-id, " +
                    $"or set the {AuthConfigEnvVar} environment variable.");
            }

            return null;
        }

        /// <summary>
        /// Builds auth JSON with federated token data for ESRPClient.exe.
        /// ESRPClient.exe contract v1.2.162+ supports FederatedTokenPath in auth JSON,
        /// pointing to a file containing the federated token data.
        /// Unlike the ESRP CLI, the access token is NOT encrypted — it's passed as a raw string.
        /// </summary>
        private string BuildFederatedTokenAuthJson()
        {
            var accessToken = Environment.GetEnvironmentVariable(_configuration.SystemAccessTokenEnvVar);
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new InvalidOperationException(
                    $"Environment variable '{_configuration.SystemAccessTokenEnvVar}' is not set. " +
                    "Required for FederatedToken auth mode.");
            }

            // Write federated token data to a temp file — ESRPClient.exe reads it via FederatedTokenPath
            var tokenData = new
            {
                JobId = GetEnv("SYSTEM_JOBID"),
                PlanId = GetEnv("SYSTEM_PLANID"),
                ProjectId = GetEnv("SYSTEM_TEAMPROJECTID"),
                Hub = GetEnv("SYSTEM_HOSTTYPE"),
                Uri = Environment.GetEnvironmentVariable("SYSTEM_COLLECTIONURI")
                    ?? GetEnv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"),
                ServiceConnectionId = _configuration.ServiceConnectionId,
                SystemAccessToken = accessToken.Trim(),
            };

            Directory.CreateDirectory(_configuration.TempDirectory);
            var tokenFilePath = Path.Combine(_configuration.TempDirectory, "esrpclient-federated-token.json");
            File.WriteAllText(tokenFilePath, JsonSerializer.Serialize(tokenData, s_compactJsonOptions));

            var auth = new
            {
                Version = "1.0.0",
                ClientId = _configuration.ClientId ?? "",
                EsrpClientId = _configuration.EsrpClientId ?? _configuration.ClientId ?? "",
                TenantId = _configuration.TenantId ?? "",
                AuthenticationType = "AAD_CERT",
                AuthCert = new
                {
                    SubjectName = $"{_configuration.ClientId}.microsoft.com",
                    StoreLocation = "LocalMachine",
                    StoreName = "My",
                    SendX5c = true,
                    GetCertFromKeyVault = true,
                    KeyVaultName = _configuration.KeyVaultName,
                    KeyVaultCertName = _configuration.CertificateName,
                },
                RequestSigningCert = new
                {
                    SubjectName = _configuration.EsrpClientId ?? _configuration.ClientId ?? "",
                    StoreLocation = "LocalMachine",
                    StoreName = "My",
                    SendX5c = false,
                },
                FederatedTokenPath = tokenFilePath,
            };
            return JsonSerializer.Serialize(auth, s_compactJsonOptions);

            static string GetEnv(string name) =>
                Environment.GetEnvironmentVariable(name) ?? "";
        }

        /// <summary>
        /// Builds the ESRP config JSON.
        /// </summary>
        internal string BuildConfigJson()
        {
            var config = new
            {
                Version = "1.0.0",
                EsrpSessionTimeoutInSec = (_configuration.TimeoutInMinutes - 5) * 60,
                MaxDegreeOfParallelism = _configuration.MaxDegreeOfParallelism,
            };
            return JsonSerializer.Serialize(config, s_compactJsonOptions);
        }

        /// <summary>
        /// Builds the ESRP policy JSON.
        /// </summary>
        internal static string BuildPolicyJson()
        {
            return JsonSerializer.Serialize(new { Version = "1.0.0" }, s_compactJsonOptions);
        }

        // ────────────────────────────────────────────────────────────────────────
        //  CLI argument construction
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Builds the command-line arguments for ESRPClient.exe Sign command.
        /// </summary>
        internal string BuildArguments(
            string submissionFile,
            string? authJson,
            string configJson,
            string policyJson,
            string outputJsonFile,
            string outputTxtFile)
        {
            var sb = new StringBuilder();
            sb.Append($"Sign -i \"{submissionFile}\"");

            if (!string.IsNullOrEmpty(authJson))
            {
                sb.Append($" -a {EscapeJsonArg(authJson)}");
            }

            sb.Append($" -c {EscapeJsonArg(configJson)}");
            sb.Append($" -p {EscapeJsonArg(policyJson)}");
            sb.Append($" -o \"{outputJsonFile}\"");
            sb.Append(" -l Verbose");
            sb.Append($" -f \"{outputTxtFile}\"");

            return sb.ToString();
        }

        /// <summary>
        /// Escapes a JSON string for use as a command-line argument on Windows.
        /// Wraps in outer double quotes and escapes inner backslashes and quotes
        /// per the Windows CRT argv parsing rules.
        /// </summary>
        internal static string EscapeJsonArg(string json)
        {
            // Windows CRT rules inside a quoted argument:
            // - 2n backslashes + " → n backslashes + end of quoted string
            // - 2n+1 backslashes + " → n backslashes + literal "
            // So we must double backslashes that precede a quote, then escape the quote.
            var sb = new StringBuilder(json.Length + 20);
            sb.Append('"');
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (c == '\\')
                {
                    // Count consecutive backslashes
                    int numBackslashes = 0;
                    while (i < json.Length && json[i] == '\\')
                    {
                        numBackslashes++;
                        i++;
                    }

                    if (i < json.Length && json[i] == '"')
                    {
                        // Backslashes before a quote: double them + escape the quote
                        sb.Append('\\', numBackslashes * 2);
                        sb.Append("\\\"");
                    }
                    else
                    {
                        // Backslashes not before a quote: emit as-is
                        sb.Append('\\', numBackslashes);
                        i--; // re-process current char
                    }
                }
                else if (c == '"')
                {
                    sb.Append("\\\"");
                }
                else
                {
                    sb.Append(c);
                }
            }
            // Before closing quote, double any trailing backslashes
            sb.Append('"');
            return sb.ToString();
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Result parsing
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Parsed result from an ESRPClient.exe invocation.
        /// </summary>
        internal sealed class ESRPClientExeResult
        {
            public bool Success { get; }
            public string? ErrorMessage { get; }

            public ESRPClientExeResult(bool success, string? errorMessage)
            {
                Success = success;
                ErrorMessage = errorMessage;
            }
        }

        /// <summary>
        /// Parses the result of an ESRPClient.exe invocation by examining exit code,
        /// stdout/stderr, output JSON, and output text.
        /// </summary>
        internal static ESRPClientExeResult ParseResult(
            int exitCode, string stdout, string stderr, string outputJson, string outputTxt)
        {
            if (exitCode != 0)
            {
                var msg = $"ESRPClient.exe exited with code {exitCode}.";
                if (!string.IsNullOrWhiteSpace(stderr))
                {
                    msg += $" stderr: {stderr.Trim()}";
                }
                if (!string.IsNullOrWhiteSpace(outputTxt))
                {
                    msg += $" output: {outputTxt.Trim()}";
                }
                return new ESRPClientExeResult(false, msg);
            }

            // Check output text for OAuth failures
            if (!string.IsNullOrEmpty(outputTxt) &&
                outputTxt.IndexOf("Invalid OAUTH token.", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return new ESRPClientExeResult(false, "ESRPClient.exe reported: Invalid OAUTH token.");
            }

            // Check output JSON for failure statuses
            if (!string.IsNullOrEmpty(outputJson))
            {
                try
                {
                    using var doc = JsonDocument.Parse(outputJson);
                    if (doc.RootElement.TryGetProperty("SubmissionResponses", out var responses))
                    {
                        foreach (var response in responses.EnumerateArray())
                        {
                            if (response.TryGetProperty("StatusCode", out var statusCode))
                            {
                                var status = statusCode.GetString();
                                if (string.Equals(status, "FailDoNotRetry", StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(status, "FailCanRetry", StringComparison.OrdinalIgnoreCase))
                                {
                                    var errorInfo = "";
                                    if (response.TryGetProperty("ErrorInfo", out var ei))
                                    {
                                        errorInfo = ei.ToString();
                                    }
                                    return new ESRPClientExeResult(false,
                                        $"ESRPClient.exe reported failure status '{status}'. ErrorInfo: {errorInfo}");
                                }
                            }
                        }
                    }
                }
                catch (JsonException)
                {
                    // If output JSON is malformed, don't fail - rely on exit code
                }
            }

            // Check for explicit failure markers in stdout
            if (!string.IsNullOrEmpty(stdout) &&
                stdout.IndexOf("failDoNotRetry", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return new ESRPClientExeResult(false, "ESRPClient.exe output contained failure marker.");
            }

            return new ESRPClientExeResult(true, null);
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Logging helpers
        // ────────────────────────────────────────────────────────────────────────

        private void LogVerbose(string message, params object[] args)
        {
            if (_configuration.VerboseLogging)
            {
                _logger.LogInformation(message, args);
            }
            else
            {
                _logger.LogDebug(message, args);
            }
        }

        private void LogDryRun(
            Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)> groups)
        {
            _logger.LogInformation("=== ESRPClient.exe Dry Run ({Count} certificate group(s)) ===", groups.Count);

            var submissionJson = BuildSubmissionJson(groups);
            _logger.LogInformation("Submission JSON:\n{Json}", submissionJson);

            var configJson = BuildConfigJson();
            _logger.LogInformation("Config JSON: {Json}", configJson);

            var policyJson = BuildPolicyJson();
            _logger.LogInformation("Policy JSON: {Json}", policyJson);

            foreach (var (certName, (_, groupFiles)) in groups)
            {
                _logger.LogInformation("  Certificate '{Cert}': {Count} file(s)", certName, groupFiles.Count);
                foreach (var (node, _) in groupFiles)
                {
                    _logger.LogInformation("    {File}", node.Location.FilePathOnDisk);
                }
            }

            _logger.LogInformation("=== End Dry Run ===");
        }

        private static string RedactAuthArguments(string arguments)
        {
            var idx = arguments.IndexOf(" -a ", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return arguments;

            var endIdx = arguments.IndexOf(" -c ", idx + 4, StringComparison.OrdinalIgnoreCase);
            if (endIdx < 0) endIdx = arguments.Length;

            return arguments[..(idx + 4)] + "[REDACTED]" + arguments[endIdx..];
        }

        private void WriteInvocationLog(ProcessResult result, string arguments)
        {
            var logDir = _configuration.LogDirectory;
            if (string.IsNullOrWhiteSpace(logDir))
            {
                return;
            }

            try
            {
                Directory.CreateDirectory(logDir);
                var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
                var logFile = Path.Combine(logDir, $"esrpclient-{timestamp}.log");

                var sb = new StringBuilder();
                sb.AppendLine("=== ESRPClient.exe Invocation ===");
                sb.AppendLine($"Timestamp (UTC): {DateTime.UtcNow:O}");
                sb.AppendLine($"Exit code: {result.ExitCode}");
                sb.AppendLine($"Arguments (redacted): {RedactAuthArguments(arguments)}");
                sb.AppendLine();
                sb.AppendLine("=== stdout ===");
                sb.AppendLine(result.StandardOutput);
                if (!string.IsNullOrWhiteSpace(result.StandardError))
                {
                    sb.AppendLine("=== stderr ===");
                    sb.AppendLine(result.StandardError);
                }

                File.WriteAllText(logFile, sb.ToString());
                _logger.LogInformation("ESRPClient.exe log written to: {LogFile}", logFile);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to write ESRPClient.exe invocation log: {Error}", ex.Message);
            }
        }

        private void TryDeleteDirectory(string path)
        {
            try { Directory.Delete(path, true); }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to delete working directory {Path}: {Error}", path, ex.Message);
            }
        }
    }
}
