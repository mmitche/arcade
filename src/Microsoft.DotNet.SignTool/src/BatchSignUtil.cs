// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Build.Framework;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;
using TaskLoggingHelper = Microsoft.Build.Utilities.TaskLoggingHelper;

namespace Microsoft.DotNet.SignTool
{
    internal sealed class BatchSignUtil
    {
        private readonly TaskLoggingHelper _log;
        private readonly IBuildEngine _buildEngine;
        private readonly BatchSignInput _batchData;
        private readonly SignTool _signTool;
        private readonly string[] _itemsToSkipStrongNameCheck;
        private readonly Dictionary<FileContentKey, string> _hashToCollisionIdMap;
        private Telemetry _telemetry;

        internal bool SkipZipContainerSignatureMarkerCheck { get; set; }

        internal BatchSignUtil(IBuildEngine buildEngine,
            TaskLoggingHelper log,
            SignTool signTool,
            BatchSignInput batchData,
            string[] itemsToSkipStrongNameCheck,
            Dictionary<FileContentKey, string> hashToCollisionIdMap,
            Telemetry telemetry = null)
        {
            _signTool = signTool;
            _batchData = batchData;
            _log = log;
            _buildEngine = buildEngine;
            _itemsToSkipStrongNameCheck = itemsToSkipStrongNameCheck ?? Array.Empty<string>();
            _telemetry = telemetry;
            _hashToCollisionIdMap = hashToCollisionIdMap;
        }

        internal void Go(bool doStrongNameCheck)
        {
            VerifyCertificates(_log);

            if (_log.HasLoggedErrors)
            {
                return;
            }

            // Next remove public signing from all of the assemblies; it can interfere with the signing process.
            RemovePublicSign();

            // Next sign all of the files
            if (!SignFiles())
            {
                _log.LogError("Error during execution of signing process.");
                return;
            }

            if (!CopyFiles())
            {
                return;
            }

            // Check that all files have a strong name signature
            if (doStrongNameCheck)
            {
                VerifyStrongNameSigning();
            }

            // Validate the signing worked and produced actual signed binaries in all locations.
            // This is a recursive process since we process nested containers.
            foreach (var file in _batchData.FilesToSign)
            {
                VerifyAfterSign(file.FileInfo);
            }

            if (_log.HasLoggedErrors)
            {
                return;
            }

            _log.LogMessage(MessageImportance.High, "Build artifacts signed and validated.");
        }

        private void RemovePublicSign()
        {
            foreach (var fileSignInfo in _batchData.FilesToSign.Where(x => x.FileInfo.IsPEFile()))
            {
                if (fileSignInfo.SignInfo.StrongName != null && fileSignInfo.SignInfo.ShouldSign)
                {
                    _log.LogMessage($"Removing public sign: '{fileSignInfo.FileName}'");
                    _signTool.RemovePublicSign(fileSignInfo.FullPath);
                }
            }
        }

        /// <summary>
        /// Actually sign all of the described files.
        /// </summary>
        private bool SignFiles()
        {
            // Generate the list of signed files in a deterministic order. Makes it easier to track down
            // bugs if repeated runs use the same ordering.
            var toProcessList = _batchData.FilesToSign.ToList();
            var toRepackSet = _batchData.FilesToSign.Where(x => x.ShouldRepack)?.Select(x => x.FullPath)?.ToHashSet();
            var round = 0;
            var trackedSet = new HashSet<FileContentKey>();

            // Given a list of files that need signing, sign them in a batch.
            bool signGroup(IEnumerable<FileWithSignInfo> files, out int signedCount)
            {
                var filesToSign = files.Where(fileInfo => fileInfo.SignInfo.ShouldSign).ToArray();
                signedCount = filesToSign.Length;
                if (filesToSign.Length == 0) return true;

                _log.LogMessage(MessageImportance.High, $"Round {round}: Signing {filesToSign.Length} files.");

                foreach (var file in filesToSign)
                {
                    string collisionIdInfo = string.Empty;
                    if(_hashToCollisionIdMap != null)
                    {
                        if(_hashToCollisionIdMap.TryGetValue(file.FileInfo.FileContentKey, out string collisionPriorityId))
                        {
                            collisionIdInfo = $"Collision Id='{collisionPriorityId}'";
                        }
                        
                    }
                    _log.LogMessage(MessageImportance.Low, $"{file} {collisionIdInfo}");
                }

                return _signTool.Sign(_buildEngine, round, filesToSign);
            }

            // Given a list of files that need signing, sign the installer engines
            // of those that are wix containers.
            bool signEngines(IEnumerable<FileWithSignInfo> files, out int signedCount)
            {
                var enginesToSign = files.Where(fileInfo => fileInfo.SignInfo.ShouldSign && 
                                                fileInfo.FileInfo.IsWixContainer() &&
                                                Path.GetExtension(fileInfo.FullPath) == ".exe").ToArray();
                signedCount = enginesToSign.Length;
                if (enginesToSign.Length == 0)
                {
                    return true;
                }

                _log.LogMessage(MessageImportance.High, $"Round {round}: Signing {enginesToSign.Length} engines.");

                Dictionary<FileContentKey, FileWithSignInfo> engines = new Dictionary<FileContentKey, FileWithSignInfo>();
                var workingDirectory = Path.Combine(_signTool.TempDir, "engines");
                int engineContainer = 0;
                // extract engines
                foreach (var file in enginesToSign)
                {
                    string engineFileName = $"{Path.Combine(workingDirectory, $"{engineContainer}", file.FileName)}{SignToolConstants.MsiEngineExtension}";
                    _log.LogMessage(MessageImportance.Normal, $"Extracting engine from {file.FullPath}");
                    if (!RunWixTool("insignia.exe", $"-ib {file.FullPath} -o {engineFileName}",
                        workingDirectory, _signTool.WixToolsPath, _log))
                    {
                        _log.LogError($"Failed to extract engine from {file.FullPath}");
                        return false;
                    }

                    var fileUniqueKey = new FileContentKey(file.FileInfo.File.ContentHash, engineFileName);

                    engines.Add(fileUniqueKey, file);
                    engineContainer++;
                }

                // sign engines
                bool signResult = _signTool.Sign(_buildEngine, round, engines.Select(engine =>
                    new FileWithSignInfo(new FileInfo(new PathWithHash(engine.Key.FileName, engine.Value.FileInfo.File.ContentHash), null, null, null), engine.Value.SignInfo)));
                if(!signResult)
                {
                    _log.LogError($"Failed to sign engines");
                    return signResult;
                }

                // attach engines
                foreach (var engine in engines)
                {
                    _log.LogMessage(MessageImportance.Normal, $"Attaching engine {engine.Key.FileName} to {engine.Value.FullPath}");

                    try
                    {
                        if (!RunWixTool("insignia.exe",
                            $"-ab {engine.Key.FileName} {engine.Value.FullPath} -o {engine.Value.FullPath}", workingDirectory,
                            _signTool.WixToolsPath, _log))
                        {
                            _log.LogError($"Failed to attach engine to {engine.Value.FullPath}");
                            return false;
                        }
                    }
                    finally
                    {
                        // cleanup engines (they fail signing verification if they stay in the drop
                        File.Delete(engine.Key.FileName);
                    }
                }
                return true;
            }

            // Given a group of file that are ready for processing,
            // repack those files that are containers.
            void repackGroup(IEnumerable<FileWithSignInfo> files, out int repackCount)
            {
                var repackList = files.Where(w => toRepackSet.Contains(w.FullPath)).ToList();

                repackCount = repackList.Count();
                if(repackCount == 0)
                {
                    return;
                }
                _log.LogMessage(MessageImportance.High, $"Repacking {repackCount} containers.");

                ParallelOptions parallelOptions = new ParallelOptions();
                parallelOptions.MaxDegreeOfParallelism = 16;
                Parallel.ForEach(repackList, parallelOptions, file =>
                {
                    if (file.FileInfo.IsZipContainer())
                    {
                        _log.LogMessage($"Repacking container: '{file.FileName}'");
                        _batchData.ZipDataMap[file.FileInfo.FileContentKey].Repack(_log, null).GetAwaiter().GetResult();
                    }
                    else if (file.FileInfo.IsWixContainer())
                    {
                        _log.LogMessage($"Packing wix container: '{file.FileName}'");
                        _batchData.ZipDataMap[file.FileInfo.FileContentKey].Repack(_log, null, _signTool.TempDir, _signTool.WixToolsPath).GetAwaiter().GetResult();
                    }
                    else
                    {
                        _log.LogError($"Don't know how to repack file '{file.FullPath}'");
                    }
                    toRepackSet.Remove(file.FullPath);
                });
            }

            // Is this file ready to be signed or repackaged? That is are all of the items that it depends on already
            // signed, don't need signing, and are repacked.
            bool isReady(FileWithSignInfo file)
            {
                if (file.FileInfo.IsContainer())
                {
                    var zipData = _batchData.ZipDataMap[file.FileInfo.FileContentKey];
                    return zipData.NestedParts.Values.All(x => (!_batchData.FileSignInfoByContentKey[x.FileInfo.FileContentKey].SignInfo.ShouldSign ||
                        trackedSet.Contains(x.FileInfo.FileContentKey)) && !toRepackSet.Contains(x.FileInfo.File.FullPath)
                        );
                }
                return true;
            }

            // Identify the next set of files that should be signed or repacked.
            // This is the set of files for which all of the dependencies have been signed,
            // are already signed, are repacked, etc.
            List<FileWithSignInfo> identifyNextGroup()
            {
                var list = new List<FileWithSignInfo>();
                var i = 0;
                while (i < toProcessList.Count)
                {
                    var current = toProcessList[i];
                    if (isReady(current))
                    {
                        list.Add(current);
                        toProcessList.RemoveAt(i);
                    }
                    else
                    {
                        i++;
                    }
                }

                return list;
            }

            // Telemetry data
            double telemetryTotalFilesSigned = 0;
            double telemetryTotalFilesRepacked = 0;
            Stopwatch telemetrySignedTime = new Stopwatch();
            Stopwatch telemetryRepackedTime = new Stopwatch();

            try
            {
                // Core algorithm of batch signing.
                // While there are files left to process,
                //  Identify which files are ready for processing (ready to repack or sign)
                //  Repack those of that set that are containers
                //  Sign any of those files that need signing, along with their engines.
                while (toProcessList.Count > 0)
                {
                    var trackList = identifyNextGroup();
                    if (trackList.Count == 0)
                    {
                        throw new InvalidOperationException("No progress made on signing which indicates a bug");
                    }

                    int fileModifiedCount;
                    telemetryRepackedTime.Start();
                    repackGroup(trackList, out fileModifiedCount);
                    telemetryRepackedTime.Stop();
                    telemetryTotalFilesRepacked += fileModifiedCount;

                    try
                    {
                        telemetrySignedTime.Start();
                        if (!signEngines(trackList, out fileModifiedCount))
                        {
                            return false;
                        }
                        if (fileModifiedCount > 0)
                        {
                            round++;
                            telemetryTotalFilesSigned += fileModifiedCount;
                        }

                        if (!signGroup(trackList, out fileModifiedCount))
                        {
                            return false;
                        }
                        if (fileModifiedCount > 0)
                        {
                            round++;
                            telemetryTotalFilesSigned += fileModifiedCount;
                        }
                    }
                    finally
                    {
                        telemetrySignedTime.Stop();
                    }

                    trackList.ForEach(x => trackedSet.Add(x.FileInfo.FileContentKey));
                }
            }
            finally
            {
                if (_telemetry != null)
                {
                    _telemetry.AddMetric("Signed file count", telemetryTotalFilesSigned);
                    _telemetry.AddMetric("Repacked file count", telemetryTotalFilesRepacked);
                    _telemetry.AddMetric("Signing duration (s)", telemetrySignedTime.ElapsedMilliseconds / 1000);
                    _telemetry.AddMetric("Repacking duration (s)", telemetryRepackedTime.ElapsedMilliseconds / 1000);
                }
            }

            return true;
        }

        internal static bool RunWixTool(string toolName, string arguments, string workingDirectory, string wixToolsPath, TaskLoggingHelper log)
        {
            if (wixToolsPath == null)
            {
                log.LogError("WixToolsPath must be defined to run WiX tooling. Wixpacks are used to produce signed msi's during post-build signing. If this repository is using in-build signing, remove '*.wixpack.zip' from ItemsToSign.");
                return false;
            }

            if (!Directory.Exists(wixToolsPath))
            {
                log.LogError($"WixToolsPath '{wixToolsPath}' not found.");
                return false;
            }

            if (!Directory.Exists(workingDirectory))
            {
                Directory.CreateDirectory(workingDirectory);
            }

            var processStartInfo = new ProcessStartInfo()
            {
                FileName = "cmd.exe",
                UseShellExecute = false,
                Arguments = $"/c {toolName} {arguments}",
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            string path = processStartInfo.EnvironmentVariables["PATH"];
            path = $"{path};{wixToolsPath}";
            processStartInfo.EnvironmentVariables.Remove("PATH");
            processStartInfo.EnvironmentVariables.Add("PATH", path);

            var process = Process.Start(processStartInfo);
            process.WaitForExit();
            return process.ExitCode == 0;
        }

        private bool CopyFiles()
        {
            bool success = true;
            foreach (var entry in _batchData.FilesToCopy)
            {
                var src = entry.Key;
                var dst = entry.Value;

                try
                {
                    _log.LogMessage($"Updating '{dst}' with signed content");
                    File.Copy(src, dst, overwrite: true);
                }
                catch (Exception e)
                {
                    _log.LogError($"Updating '{dst}' with signed content failed: '{e.Message}'");
                    success = false;
                }
            }

            return success;
        }

        /// <summary>
        /// Sanity check the certificates that are attached to the various items. Ensure we aren't using, say, a VSIX
        /// certificate on a DLL for example.
        /// </summary>
        private void VerifyCertificates(TaskLoggingHelper log)
        {
            foreach (var fileName in _batchData.FilesToSign.OrderBy(x => x.FullPath))
            {
                bool isVsixCert = (!string.IsNullOrEmpty(fileName.SignInfo.Certificate) && IsVsixCertificate(fileName.SignInfo.Certificate)) ||
                                    fileName.SignInfo.IsAlreadySigned && fileName.HasSignableParts;

                bool isInvalidEmptyCertificate = fileName.SignInfo.Certificate == null && !fileName.HasSignableParts && !fileName.SignInfo.IsAlreadySigned;

                FileInfo fileInfo = fileName.FileInfo;

                if (fileInfo.IsPEFile())
                {
                    if (isVsixCert)
                    {
                        log.LogError($"Assembly {fileName} cannot be signed with a VSIX certificate");
                    }
                }
                else if (fileName.FileInfo.IsVsix())
                {
                    if (!isVsixCert)
                    {
                        log.LogError($"VSIX {fileName} must be signed with a VSIX certificate");
                    }

                    if (fileName.SignInfo.StrongName != null)
                    {
                        log.LogError($"VSIX {fileName} cannot be strong name signed.");
                    }
                }
                else if (fileName.FileInfo.IsNupkg())
                {
                    if (isInvalidEmptyCertificate)
                    {
                        log.LogError($"Nupkg {fileName} should have a certificate name.");
                    }

                    if (fileName.SignInfo.StrongName != null)
                    {
                        log.LogError($"Nupkg {fileName} cannot be strong name signed.");
                    }
                }
                else if (fileName.FileInfo.IsZip())
                {
                    if (fileName.SignInfo.Certificate != null)
                    {
                        log.LogError($"Zip {fileName} should not be signed with this certificate: {fileName.SignInfo.Certificate}");
                    }

                    if (fileName.SignInfo.StrongName != null)
                    {
                        log.LogError($"Zip {fileName} cannot be strong name signed.");
                    }
                }
                if (fileName.FileInfo.IsExecutableWixContainer())
                {
                    if (isInvalidEmptyCertificate)
                    {
                        log.LogError($"Wix file {fileName} should have a certificate name.");
                    }

                    if (fileName.SignInfo.StrongName != null)
                    {
                        log.LogError($"Wix file {fileName} cannot be strong name signed.");
                    }
                }
            }
        }

        private void VerifyAfterSign(FileInfo fileInfo)
        {
            if (fileInfo.IsPEFile())
            {
                using (var stream = File.OpenRead(fileInfo.File.FullPath))
                {
                    if (!_signTool.VerifySignedPEFile(stream))
                    {
                        _log.LogError($"Assembly {fileInfo.File.FullPath} is NOT signed properly");
                    }
                    else
                    {
                        _log.LogMessage(MessageImportance.Low, $"Assembly {fileInfo.File.FullPath} is signed properly");
                    }
                }
            }
            else if (fileInfo.IsPowerShellScript())
            {
                if (!_signTool.VerifySignedPowerShellFile(fileInfo.File.FullPath))
                {
                    _log.LogError($"Powershell file {fileInfo.File.FullPath} does not have a signature mark.");
                }
            }
            else if (fileInfo.IsZipContainer())
            {
                var zipData = _batchData.ZipDataMap[fileInfo.FileContentKey];
                bool signedContainer = false;

                using (var archive = new ZipArchive(File.OpenRead(fileInfo.File.FullPath), ZipArchiveMode.Read))
                {
                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        string relativeName = entry.FullName;

                        if (!SkipZipContainerSignatureMarkerCheck)
                        {
                            if (fileInfo.IsNupkg() && _signTool.VerifySignedNugetFileMarker(relativeName))
                            {
                                signedContainer = true;
                            }
                            else if (fileInfo.IsVsix() && _signTool.VerifySignedVSIXFileMarker(relativeName))
                            {
                                signedContainer = true;
                            }
                        }

                        var zipPart = zipData.FindNestedPart(relativeName);
                        if (!zipPart.HasValue)
                        {
                            continue;
                        }

                        VerifyAfterSign(zipPart.Value.FileInfo);
                    }
                }

                if (!SkipZipContainerSignatureMarkerCheck)
                {
                    if ((fileInfo.IsNupkg() || fileInfo.IsVsix()) && !signedContainer)
                    {
                        _log.LogError($"Container {fileInfo.File.FullPath} does not have signature marker.");
                    }
                    else
                    {
                        _log.LogMessage(MessageImportance.Low, $"Container {fileInfo.File.FullPath} has a signature marker.");
                    }
                }
            }
        }

        private void VerifyStrongNameSigning()
        {
            foreach (var file in _batchData.FilesToSign)
            {
                if (_itemsToSkipStrongNameCheck.Contains(file.FileName))
                {
                    _log.LogMessage($"Skipping strong-name validation for {file.FullPath}.");
                    continue;
                }

                FileInfo fileInfo = file.FileInfo;
                if (fileInfo.IsManaged() && !fileInfo.IsCrossgened() && !_signTool.VerifyStrongNameSign(file.FullPath))
                {
                    _log.LogError($"Assembly {file.FullPath} is not strong-name signed correctly.");
                }
                else
                {
                    _log.LogMessage(MessageImportance.Low, $"Assembly {file.FullPath} strong-name signature is valid.");
                }
            }
        }

        private static bool IsVsixCertificate(string certificate) => certificate.StartsWith("Vsix", StringComparison.OrdinalIgnoreCase);
    }
}
