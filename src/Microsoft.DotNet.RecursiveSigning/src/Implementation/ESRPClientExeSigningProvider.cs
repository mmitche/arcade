// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    /// Signing provider that invokes ESRPClient.exe using the Sign command.
    /// Builds a full submission JSON with SignBatches (one per certificate) and submits
    /// all files in a single ESRPClient.exe invocation.
    /// </summary>
    public sealed class ESRPClientExeSigningProvider : ESRPSigningProviderBase
    {
        private readonly ESRPClientExeSigningConfiguration _configuration;

        /// <summary>
        /// Environment variable name that ESRPClient.exe reads for auth configuration.
        /// When this is set, explicit auth parameters are not required.
        /// </summary>
        internal const string AuthConfigEnvVar = "ESRP_AUTH_CONFIG";

        public ESRPClientExeSigningProvider(
            ESRPClientExeSigningConfiguration configuration,
            IProcessRunner processRunner,
            ILogger<ESRPClientExeSigningProvider> logger)
            : base(processRunner, logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        protected override ESRPSigningConfiguration Configuration => _configuration;
        protected override string ProviderName => "ESRPClient.exe";

        protected override async Task<bool> ExecuteSigningAsync(
            Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)> groups,
            IReadOnlyList<(FileNode node, string outputPath)> allFiles,
            CancellationToken cancellationToken)
        {
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

                var result = await ProcessRunner.RunAsync(
                    _configuration.ESRPClientExePath, arguments, cancellationToken);

                LogVerbose("ESRPClient.exe stdout:\n{Stdout}", result.StandardOutput);
                if (!string.IsNullOrWhiteSpace(result.StandardError))
                {
                    LogVerbose("ESRPClient.exe stderr:\n{Stderr}", result.StandardError);
                }

                // Write invocation log
                WriteInvocationLog(
                    "ESRPClient.exe Invocation", "esrpclient",
                    result, RedactAuthArguments(arguments));

                // Parse output
                var outputJson = File.Exists(outputJsonFile) ? File.ReadAllText(outputJsonFile) : "";
                var outputTxt = File.Exists(outputTxtFile) ? File.ReadAllText(outputTxtFile) : "";

                var parsed = ParseResult(result.ExitCode, result.StandardOutput, result.StandardError, outputJson, outputTxt);

                if (!parsed.Success)
                {
                    Logger.LogError("ESRPClient.exe signing failed: {Error}", parsed.ErrorMessage);
                    return false;
                }

                Logger.LogInformation("ESRPClient.exe signing succeeded for all {Count} file(s)", allFiles.Count);

                // Attach provider-specific signing details to each node
                foreach (var (certName, (_, groupFiles)) in groups)
                {
                    var signingDetails = new ESRPClientExeSigningDetails(certName);
                    foreach (var (node, _) in groupFiles)
                    {
                        node.SigningDetails = signingDetails;
                    }
                }

                return true;
            }
            finally
            {
                TryDeleteDirectory(workDir);
            }
        }

        protected override void LogDryRun(
            Dictionary<string, (ESRPCertificateIdentifier cert, List<(FileNode node, string outputPath)> files)> groups)
        {
            Logger.LogInformation("=== ESRPClient.exe Dry Run ({Count} certificate group(s)) ===", groups.Count);

            var submissionJson = BuildSubmissionJson(groups);
            Logger.LogInformation("Submission JSON:\n{Json}", submissionJson);

            var configJson = BuildConfigJson();
            Logger.LogInformation("Config JSON: {Json}", configJson);

            var policyJson = BuildPolicyJson();
            Logger.LogInformation("Policy JSON: {Json}", policyJson);

            foreach (var (certName, (_, groupFiles)) in groups)
            {
                Logger.LogInformation("  Certificate '{Cert}': {Count} file(s)", certName, groupFiles.Count);
                foreach (var (node, _) in groupFiles)
                {
                    Logger.LogInformation("    {File}", node.Location.FilePathOnDisk);
                }
            }

            Logger.LogInformation("=== End Dry Run ===");
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
                var operations = ExtractOperations(cert.CertificateDefinition);

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

            return JsonSerializer.Serialize(submission, PrettyJsonOptions);
        }

        // ────────────────────────────────────────────────────────────────────────
        //  Auth / Config / Policy JSON
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Builds auth JSON from configuration parameters, or reads from the
        /// <c>ESRP_AUTH_CONFIG</c> environment variable.
        /// Returns null if auth should be handled by the environment variable directly.
        /// </summary>
        internal string? BuildAuthJson()
        {
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
                    AuthCert = new
                    {
                        SubjectName = $"{_configuration.ClientId}.microsoft.com",
                        StoreLocation = "LocalMachine",
                        StoreName = "My",
                        SendX5c = true,
                    },
                    RequestSigningCert = new
                    {
                        SubjectName = _configuration.EsrpClientId ?? _configuration.ClientId,
                        StoreLocation = "LocalMachine",
                        StoreName = "My",
                        SendX5c = false,
                    },
                };
                return JsonSerializer.Serialize(auth, CompactJsonOptions);
            }

            // Check ESRP_AUTH_CONFIG environment variable
            var envAuthConfig = Environment.GetEnvironmentVariable(AuthConfigEnvVar);
            if (!string.IsNullOrEmpty(envAuthConfig))
            {
                Logger.LogInformation("Using auth configuration from {EnvVar} environment variable", AuthConfigEnvVar);
                return envAuthConfig;
            }

            if (!_configuration.DryRun)
            {
                throw new InvalidOperationException(
                    $"No auth configuration provided. Supply --esrp-client-id/--esrp-app-registration/--esrp-tenant-id, " +
                    $"or set the {AuthConfigEnvVar} environment variable.");
            }

            return null;
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
            return JsonSerializer.Serialize(config, CompactJsonOptions);
        }

        /// <summary>
        /// Builds the ESRP policy JSON.
        /// </summary>
        internal static string BuildPolicyJson()
        {
            return JsonSerializer.Serialize(new { Version = "1.0.0" }, CompactJsonOptions);
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
        /// Escapes a JSON string for use as a command-line argument.
        /// Replaces inner quotes with escaped quotes, matching the
        /// approach used by the Sign repo's ESRPClientExe.EscapeJson.
        /// </summary>
        internal static string EscapeJsonArg(string json)
        {
            return json.Replace("\"", "\\\"");
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
        //  Auth redaction
        // ────────────────────────────────────────────────────────────────────────

        private static string RedactAuthArguments(string arguments)
        {
            var idx = arguments.IndexOf(" -a ", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return arguments;

            var endIdx = arguments.IndexOf(" -c ", idx + 4, StringComparison.OrdinalIgnoreCase);
            if (endIdx < 0) endIdx = arguments.Length;

            return arguments[..(idx + 4)] + "[REDACTED]" + arguments[endIdx..];
        }
    }
}
