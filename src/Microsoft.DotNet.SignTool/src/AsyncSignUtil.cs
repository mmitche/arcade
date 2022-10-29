// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Build.Framework;
using Microsoft.Build.Framework.XamlTypes;
using static System.Net.WebRequestMethods;
using ITaskItem = Microsoft.Build.Framework.ITaskItem;
using TaskLoggingHelper = Microsoft.Build.Utilities.TaskLoggingHelper;

namespace Microsoft.DotNet.SignTool
{
    internal class AsyncSignUtil
    {
        private readonly TaskLoggingHelper _log;

        private readonly Microsoft.Build.Framework.ITaskItem[] _itemsToSign;

        /// <summary>
        /// This store content information for container files.
        /// Key is the content hash of the file.
        /// </summary>
        private readonly ConcurrentDictionary<FileContentKey, Task<ZipData>> _zipDataMap;
        // Locks to avoid race conditions around unpack of archives
        // or the files within archives. The archives themselves have a race in
        // Unpack where the UnpackImpl task in the zip data map would be launched twice without one.
        // So we 
        public ConcurrentDictionary<FileContentKey, object> _zipDataLocks = new ConcurrentDictionary<FileContentKey, object>();

        /// <summary>
        /// Path to where container files will be extracted.
        /// </summary>
        private readonly string _pathToContainerUnpackingDirectory;

        /// <summary>
        /// This enable the overriding of the default certificate for a given file+token+target_framework.
        /// It also contains a SignToolConstants.IgnoreFileCertificateSentinel flag in the certificate name in case the file does not need to be signed
        /// for that 
        /// </summary>
        private readonly ImmutableDictionary<ExplicitCertificateKey, string> _fileSignInfo;

        /// <summary>
        /// Used to look for signing information when we have the PublicKeyToken of a file.
        /// </summary>
        private readonly ImmutableDictionary<string, List<SignInfo>> _strongNameInfo;

        /// <summary>
        /// A list of all the binaries that MUST be signed. Also include containers that don't need 
        /// to be signed themselves but include files that must be signed.
        /// </summary>
        private readonly ConcurrentBag<FileWithSignInfo> _filesToSign;

        private ImmutableList<WixPackInfo> _wixPacks;

        /// <summary>
        /// Mapping of ".ext" to certificate. Files that have an extension on this map
        /// will be signed using the specified certificate. Input list might contain
        /// duplicate entries
        /// </summary>
        private readonly ImmutableDictionary<string, List<SignInfo>> _fileExtensionSignInfo;

        private readonly ConcurrentDictionary<FileContentKey, FileWithSignInfo> _filesSignInfoByContentKey;

        private readonly ConcurrentDictionary<FileContentKey, Task> _signingTasksByContentKey;

        /// <summary>
        /// For each uniquely identified file keeps track of all containers where the file appeared.
        /// </summary>
        private readonly ConcurrentDictionary<FileContentKey, HashSet<string>> _parentContainerMapping;

        /// <summary>
        /// Keeps track of all files that produced a given error code.
        /// </summary>
        private readonly ConcurrentDictionary<SigningToolErrorCode, HashSet<FileContentKey>> _errors;

        /// <summary>
        /// This is a list of the friendly name of certificates that can be used to
        /// sign already signed binaries.
        /// </summary>
        private readonly ITaskItem[] _dualCertificates;

        /// <summary>
        /// Use the content hash in the path of the extracted file paths. 
        /// The default is to use a unique content id based on the number of items extracted.
        /// </summary>
        private readonly bool _useHashInExtractionPath;

        /// <summary>
        /// A list of files whose content needs to be overwritten by signed content from a different file.
        /// Copy the content of file with full path specified in Key to file with full path specified in Value.
        /// </summary>
        internal ConcurrentBag<KeyValuePair<string, string>> _filesToCopy;

        /// <summary>
        /// Maps file hashes to collision ids. We use this to determine whether we processed an asset already
        /// and what collision id to use. We always choose the lower collision id in case of collisions.
        /// </summary>
        internal ConcurrentDictionary<FileContentKey, string> _hashToCollisionIdMap;

        private readonly IBuildEngine _buildEngine;
        private readonly SignTool _signTool;

        private Telemetry _telemetry;

        // We must complete all unpack and examination tasks on all lower correlation IDs
        // before we can start the examination task for a higher ID. The way this is done
        // is that we keep a dictionary of all the unpack and examine tasks by correlation ID.
        // Before starting the examine task for a higher correlation id, wait on all lower correlation IDs.
        // We can avoid a huge dictionary (due to a large number of files) by only tracking the top level files.
        // The required order of operations is that a file must have been unpacked recursively before it can
        // be examined, so by extension if the top level has had its examination, then we can proceed.
        Dictionary<string, List<Task>> _topLevelUnpackTasksByCollisionPriorityId = new Dictionary<string, List<Task>>();

        public AsyncSignUtil(
            string tempDir,
            ITaskItem[] itemsToSign,
            ImmutableDictionary<string, List<SignInfo>> strongNameInfo,
            ImmutableDictionary<ExplicitCertificateKey, string> fileSignInfo,
            ImmutableDictionary<string, List<SignInfo>> extensionSignInfo,
            ITaskItem[] dualCertificates,
            TaskLoggingHelper log,
            bool useHashInExtractionPath = false,
            Telemetry telemetry = null)
        {
            Debug.Assert(tempDir != null);
            Debug.Assert(itemsToSign != null && !itemsToSign.Any(i => i == null));
            Debug.Assert(strongNameInfo != null);
            Debug.Assert(fileSignInfo != null);

            _pathToContainerUnpackingDirectory = Path.Combine(tempDir, "ContainerSigning");
            _useHashInExtractionPath = useHashInExtractionPath;
            _log = log;
            _strongNameInfo = strongNameInfo;
            _fileSignInfo = fileSignInfo;
            _fileExtensionSignInfo = extensionSignInfo;
            _filesToSign = new ConcurrentBag<FileWithSignInfo>();
            _filesToCopy = new ConcurrentBag<KeyValuePair<string, string>>();
            _zipDataMap = new ConcurrentDictionary<FileContentKey, Task<ZipData>>();
            _filesSignInfoByContentKey = new ConcurrentDictionary<FileContentKey, FileWithSignInfo>();
            _signingTasksByContentKey = new ConcurrentDictionary<FileContentKey, Task>();
            _itemsToSign = itemsToSign;
            _dualCertificates = dualCertificates == null ? new ITaskItem[0] : dualCertificates;
            _parentContainerMapping = new ConcurrentDictionary<FileContentKey, HashSet<string>>();
            _errors = new ConcurrentDictionary<SigningToolErrorCode, HashSet<FileContentKey>>();
            _wixPacks = _itemsToSign.Where(w => WixPackInfo.IsWixPack(w.ItemSpec))?.Select(s => new WixPackInfo(s.ItemSpec)).ToImmutableList();
            _hashToCollisionIdMap = new ConcurrentDictionary<FileContentKey, string>();
            _telemetry = telemetry;
        }

        public async Task Go()
        {
            ConcurrentBag<Task> tasks = new ConcurrentBag<Task>();

            Stopwatch signTime = Stopwatch.StartNew();

            try
            {
                var inputFiles = CreateInitialnputList();

                foreach (var file in inputFiles)
                {
                    tasks.Add(ProcessFile(file, tasks, 0));
                }

                await Task.WhenAll(tasks);
            }
            finally
            {
                signTime.Stop();
            }
        }

        /// <summary>
        /// Recursively process files.
        /// </summary>
        /// <param name="file"></param>
        /// <param name="tasks"></param>
        /// <param name="depth"></param>
        /// <remarks>
        ///     It's important that no recursion happen within throttled async tasks. For instance,
        ///     unpack should complete and then we should look at the file contents. NOT recurse as we unpack the contents.</remarks>
        /// <returns></returns>
        public async Task ProcessFile(FileInfo file, ConcurrentBag<Task> tasks, int depth)
        {
            // A file may not be unpacked or examined if it has a higher than other tasks that are
            // in the unpack stage. This means all top level unpack tasks should have been finished.
            if (!string.IsNullOrEmpty(file.CollisionPriorityId))
            {
                // I'm not sure whether this is going to be slow or not. Number of keys in the dictionary is low.
                // We could avoid the WhenAll by ref counting or something like that, or by removing
                // completed tasks from the dictionary. Anyways since this only top level tasks, I'm hesitant
                // to optimize until need be.
                var tasksThatMustCompleteBeforeProcessing = _topLevelUnpackTasksByCollisionPriorityId
                    .Where(kv => kv.Key.CompareTo(file.CollisionPriorityId) < 0)
                    .Select(kv => kv.Value)
                    .SelectMany(t => t);

                _log.LogMessage($"File {file.File.FullPath} with CPID {file.CollisionPriorityId} waiting on {tasksThatMustCompleteBeforeProcessing.Count()} before continuing.");
                await Task.WhenAll(tasksThatMustCompleteBeforeProcessing);
            }

            List<Task> examinationDependencies = new List<Task>();
            if (file.IsContainer())
            {
                // Unpack and recurse on the sub items
                var unpackTask = Unpack(file);

                if (file.CollisionPriorityId != null && depth == 0)
                {
                    // Add to top level tasks
                    _topLevelUnpackTasksByCollisionPriorityId[file.CollisionPriorityId].Add(unpackTask);
                }

                var zipData = await unpackTask;

                // Walk all nested parts and process.
                foreach (var nestedFile in zipData.NestedParts)
                {
                    // This isn't totally optimal here. It blocks examination on signing
                    // and repacking of sub-dependencies, which is not exactly required.
                    // Practically, it's prooobably fine, because examination is fast,
                    // and you'd have to block on sign next anyway
                    examinationDependencies.Add(ProcessFile(nestedFile.Value.FileInfo, tasks, depth + 1));
                }
            }

            // Wait on the examinationDependencies before attempting to determine the signing
            // certs. This is important because a container's signing cert (and whether it will be signed at all)
            // can be dependent on the contents.

            await Task.WhenAll(examinationDependencies);

            var fileWithSignInfo = Examine(file);

            if (fileWithSignInfo.ShouldRepack)
            {
                await Repack(fileWithSignInfo);
            }

            if (fileWithSignInfo.ShouldSign)
            {
                await Sign(fileWithSignInfo);
            }
        }

        ReaderWriterLockSlim _signBatchAwaitersLock = new ReaderWriterLockSlim();
        public Dictionary<int, (ConcurrentBag<FileWithSignInfo> batch, Task<bool> batchAwaiter)> _signBatchAwaiters =
            new Dictionary<int, (ConcurrentBag<FileWithSignInfo>, Task<bool>)>()

        public async Task Repack(FileWithSignInfo fileWithSignInfo)
        {
            
        }

        /// <summary>
        /// Sign files
        /// </summary>
        /// <param name="fileWithSignInfo"></param>
        /// <returns></returns>
        public async Task<bool> Sign(FileWithSignInfo fileWithSignInfo)
        {
            EnsureAtLeastOneBatchAwaiter();

            try
            {
                _signBatchAwaitersLock.EnterReadLock();

                // Add the file to the last entry in the dictionary (based on Count)
                var (batch, batchAwaiter) = _signBatchAwaiters[_signBatchAwaiters.Count];
                batch.Add(fileWithSignInfo);
                return await batchAwaiter;
            }
            finally
            {
                _signBatchAwaitersLock.ExitReadLock();
            }
        }

        public void EnsureAtLeastOneBatchAwaiter()
        {
            if (_signBatchAwaiters.Count != 0)
            {
                return;
            }

            // Only add the sign batch awaiter if count is still 0 after entering the lock
            AddNewBatchAwaiter(() => _signBatchAwaiters.Count == 0);
        }

        private void AddNewBatchAwaiter(Func<bool> pred = null)
        {
            // Enter the write lock and try again
            try
            {
                _signBatchAwaitersLock.EnterWriteLock();

                if (pred != null && pred())
                {
                    var newBatch = new ConcurrentBag<FileWithSignInfo>();
                    var newBatchNumber = _signBatchAwaiters.Count;
                    var newAwaiter = SignBatchAwaiter(newBatch, newBatchNumber);
                    _signBatchAwaiters.Add(newBatchNumber, (newBatch, newAwaiter));
                }
            }
            finally
            {
                _signBatchAwaitersLock.ExitWriteLock();
            }
        }

        public const int _minBatchTriggerSize = 100;
        public const int _maxIdleTimeInSeconds = 10;

        public async Task<bool> SignBatchAwaiter(ConcurrentBag<FileWithSignInfo> files, int batch)
        {
            // There are two triggers for this batch:
            // Ran over the minimum number of files
            // was idle for more than N seconds.

            int previousCount;
            do
            {
                previousCount = files.Count;
                await Task.Delay((int)TimeSpan.FromSeconds(_maxIdleTimeInSeconds).TotalMilliseconds);
            }
            while (files.Count < _minBatchTriggerSize && previousCount != files.Count);

            // Create the new batch before flushing this one
            AddNewBatchAwaiter();

            // At this point, all new files are going to the next batch,
            // And this can be signed and finished.

            return await SignBatch(files, batch);
        }

        public Task<bool> SignBatch(IEnumerable<FileWithSignInfo> files, int batch)
        {
            _log.LogMessage(MessageImportance.High, $"Batch {batch}: Signing {files.Length} files.");

            foreach (var file in files)
            {
                string collisionIdInfo = string.Empty;
                if (_hashToCollisionIdMap != null)
                {
                    if (_hashToCollisionIdMap.TryGetValue(file.FileInfo.FileContentKey, out string collisionPriorityId))
                    {
                        collisionIdInfo = $"Collision Id='{collisionPriorityId}'";
                    }

                }
                _log.LogMessage(MessageImportance.Low, $"{file} {collisionIdInfo}");
            }

            return Task.FromResult(_signTool.Sign(_buildEngine, batch, files));
        }

        public SemaphoreSlim _unpackThrottle = new SemaphoreSlim(4, 4);

        /// <summary>
        /// Unpacks a container and updates the _zipData structure.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public Task<ZipData> Unpack(FileInfo file)
        {
            // First, see whether we need to unpack this at all. If the
            // zip data map already contains this file entry, no need to continue, just
            // return the task.
            if (_zipDataMap.TryGetValue(file.FileContentKey, out var zipData))
            {
                return zipData;
            }

            // The point of using the concurrent zip data map AND the lock is that
            // we want to avoid starting the unpack task twice for the same input
            // file content key. When we TryAdd to the zip data map, the Task will
            // start. We only want to start it once. So we really need a lock. We could
            // get clever and attempt to use the concurrent dictionary entries as the lock
            // (e.g. adding a new task that does nothing, then starting afterwards), but other threads
            // accessing the dictionary will need to return the real task. While this appears a bit messy, it's
            // a bit easier to attempt to add a new object to a CD, then if you can, lock it. If you can't, lock
            // the object that did get added. Then the first thread to enter the lock gets to start the task, and
            // the second thread does nothing, and just returns the task that got started.
            var unpackLock = new object();
            if (!_zipDataLocks.TryAdd(file.FileContentKey, unpackLock))
            {
                unpackLock = _zipDataLocks[file.FileContentKey];
            }

            lock (unpackLock)
            {
                // Read value again. If it exists, then no need to start.
                // That means someone entered this mutex before us and we should just return the
                // value. Otherwise, 
                if (!_zipDataMap.ContainsKey(file.FileContentKey))
                {
                    if (!_zipDataMap.TryAdd(file.FileContentKey, UnpackImpl(file)))
                    {
                        throw new Exception($"Expected that {file.File.FullPath} @ {file.FileContentKey.StringHash} has lock to unpack");
                    }
                }
            }

            // Now the task should have been started
            return _zipDataMap[file.FileContentKey];
        }

        public async Task<ZipData> UnpackImpl(FileInfo file)
        {
            try
            {
                await _unpackThrottle.WaitAsync();

                if (file.IsZipContainer())
                {
                    return await TryBuildZipData(file);
                }
                else if (file.IsWixContainer())
                {
                    _log.LogMessage($"Trying to gather data for wix container {file.File.FullPath}");
                    return await TryBuildWixData(file);
                }
                else
                {
                    throw new NotImplementedException("Unknown container type");
                }
            }
            finally
            {
                _unpackThrottle.Release();
            }
        }

        public FileWithSignInfo Examine(FileInfo fileToExamine)
        {
            // If the file's signing info has already been computed, no need to do anything.
            // This is largely an optimization. ComputeSigningInfo does not mutate state.
            if (_filesSignInfoByContentKey.TryGetValue(fileToExamine.FileContentKey, out var fileWIthSignInfo))
            {
                return fileWIthSignInfo;
            }

            var signingInfo = ComputeSigningInfo(fileToExamine);

            // Add to map or return value current in the map.
            if (_filesSignInfoByContentKey.TryAdd(fileToExamine.FileContentKey, signingInfo))
            {
                return signingInfo;
            }
            else
            {
                return _filesSignInfoByContentKey[fileToExamine.FileContentKey];
            }
        }

        private FileWithSignInfo ComputeSigningInfo(FileInfo fileToExamine)
        {
            PathWithHash file = fileToExamine.File;
            PathWithHash parentContainer = fileToExamine.ParentContainer;
            string collisionPriorityId = fileToExamine.CollisionPriorityId;

            var extension = Path.GetExtension(fileToExamine.File.FileName);
            string explicitCertificateName = null;
            var fileSpec = string.Empty;
            var isAlreadySigned = false;
            var matchedNameTokenFramework = false;
            var matchedNameToken = false;
            var matchedName = false;
            PEInfo peInfo = null;
            FileContentKey signedFileContentKey = new FileContentKey(file.ContentHash, file.FileName);

            // handle multi-part extensions like ".symbols.nupkg" specified in FileExtensionSignInfo
            if (_fileExtensionSignInfo != null)
            {
                extension = _fileExtensionSignInfo.OrderByDescending(o => o.Key.Length).FirstOrDefault(f => file.FileName.EndsWith(f.Key, StringComparison.OrdinalIgnoreCase)).Key ?? extension;
            }

            Debug.Assert(_hashToCollisionIdMap[signedFileContentKey] == collisionPriorityId);

            // Try to determine default certificate name by the extension of the file. Since there might be dupes
            // we get the one which maps a collision id or the first of the returned ones in case there is no
            // collision id
            bool hasSignInfos = _fileExtensionSignInfo.TryGetValue(extension, out var signInfos);
            SignInfo signInfo = SignInfo.Ignore;
            bool hasSignInfo = false;

            if (hasSignInfos)
            {
                if (!string.IsNullOrEmpty(collisionPriorityId))
                {
                    hasSignInfo = signInfos.Where(s => s.CollisionPriorityId == collisionPriorityId).Any();
                    signInfo = signInfos.Where(s => s.CollisionPriorityId == collisionPriorityId).FirstOrDefault();
                }
                else
                {
                    hasSignInfo = true;
                    signInfo = signInfos.FirstOrDefault();
                }
            }

            if (FileInfo.IsPEFile(file.FullPath))
            {
                using (var stream = File.OpenRead(file.FullPath))
                {
                    isAlreadySigned = ContentUtil.IsAuthenticodeSigned(stream);
                }

                peInfo = ContentUtil.GetPEInfo(file.FullPath);

                if (peInfo.IsManaged && _strongNameInfo.TryGetValue(peInfo.PublicKeyToken, out var pktBasedSignInfos))
                {
                    // Get the default sign info based on the PKT, if applicable. Since there might be dupes
                    // we get the one which maps a collision id or the first of the returned ones in case there is no
                    // collision id
                    SignInfo pktBasedSignInfo = SignInfo.Ignore;

                    if (!string.IsNullOrEmpty(collisionPriorityId))
                    {
                        pktBasedSignInfo = pktBasedSignInfos.Where(s => s.CollisionPriorityId == collisionPriorityId).FirstOrDefault();
                    }
                    else
                    {
                        pktBasedSignInfo = pktBasedSignInfos.FirstOrDefault();
                    }

                    if (peInfo.IsCrossgened)
                    {
                        signInfo = new SignInfo(pktBasedSignInfo.Certificate, collisionPriorityId);
                    }
                    else
                    {
                        signInfo = pktBasedSignInfo;
                    }

                    hasSignInfo = true;
                }

                // Check if we have more specific sign info:
                matchedNameTokenFramework = _fileSignInfo.TryGetValue(
                    new ExplicitCertificateKey(file.FileName, peInfo.PublicKeyToken, peInfo.TargetFramework, collisionPriorityId),
                    out explicitCertificateName);
                matchedNameToken = !matchedNameTokenFramework && _fileSignInfo.TryGetValue(
                    new ExplicitCertificateKey(file.FileName, peInfo.PublicKeyToken, collisionPriorityId: collisionPriorityId),
                    out explicitCertificateName);

                fileSpec = matchedNameTokenFramework ? $" (PublicKeyToken = {peInfo.PublicKeyToken}, Framework = {peInfo.TargetFramework})" :
                        matchedNameToken ? $" (PublicKeyToken = {peInfo.PublicKeyToken})" : string.Empty;
            }
            else if (FileInfo.IsNupkg(file.FullPath) || FileInfo.IsVsix(file.FullPath))
            {
                isAlreadySigned = VerifySignatures.IsSignedContainer(file.FullPath);
                if (!isAlreadySigned)
                {
                    _log.LogMessage(MessageImportance.Low, $"Container {file.FullPath} does not have a signature marker.");
                }
                else
                {
                    _log.LogMessage(MessageImportance.Low, $"Container {file.FullPath} has a signature marker.");
                }
            }
            else if (FileInfo.IsWix(file.FullPath))
            {
                isAlreadySigned = VerifySignatures.IsDigitallySigned(file.FullPath);
                if (!isAlreadySigned)
                {
                    _log.LogMessage(MessageImportance.Low, $"File {file.FullPath} is not digitally signed.");
                }
                else
                {
                    _log.LogMessage(MessageImportance.Low, $"File {file.FullPath} is digitally signed.");
                }
            }
            else if (FileInfo.IsPowerShellScript(file.FullPath))
            {
                isAlreadySigned = VerifySignatures.VerifySignedPowerShellFile(file.FullPath);
                if (!isAlreadySigned)
                {
                    _log.LogMessage(MessageImportance.Low, $"File {file.FullPath} does not have a signature block.");
                }
                else
                {
                    _log.LogMessage(MessageImportance.Low, $"File {file.FullPath} has a signature block.");
                }
            }

            // We didn't find any specific information for PE files using PKT + TargetFramework
            if (explicitCertificateName == null)
            {
                matchedName = _fileSignInfo.TryGetValue(new ExplicitCertificateKey(file.FileName, collisionPriorityId), out explicitCertificateName);
            }

            // If has overriding info, is it for ignoring the file?
            if (SignToolConstants.IgnoreFileCertificateSentinel.Equals(explicitCertificateName, StringComparison.OrdinalIgnoreCase))
            {
                _log.LogMessage(MessageImportance.Low, $"File configured to not be signed: {file.FullPath}{fileSpec}");
                return new FileWithSignInfo(fileToExamine, SignInfo.Ignore);
            }

            // Do we have an explicit certificate after all?
            if (explicitCertificateName != null)
            {
                signInfo = signInfo.WithCertificateName(explicitCertificateName, collisionPriorityId);
                hasSignInfo = true;
            }

            // Only sign containers if the file itself is unsigned, or 
            // an item in the container is unsigned. If the file is already signed but
            // has parts that need signing, then the container itself will have its signature invalidated
            // and will need to be re-signed.
            bool hasSignableParts = false;

            if (fileToExamine.IsContainer())
            {
                var zipData = await _zipDataMap[fileToExamine.FileContentKey];
                hasSignableParts = zipData.NestedParts.Values.Any(b =>
                {
                    var signInfo = _filesSignInfoByContentKey[b.FileInfo.FileContentKey];
                    return signInfo.ShouldSign || signInfo.HasSignableParts;
                });

                if (hasSignableParts)
                {
                    isAlreadySigned = false;
                }
            }

            if (hasSignInfo)
            {
                bool dualCerts = _dualCertificates
                        .Where(d => d.ItemSpec == signInfo.Certificate &&
                        (d.GetMetadata(SignToolConstants.CollisionPriorityId) == "" ||
                        d.GetMetadata(SignToolConstants.CollisionPriorityId) == collisionPriorityId)).Any();

                if (isAlreadySigned && !dualCerts)
                {
                    return new FileWithSignInfo(fileToExamine, signInfo.WithIsAlreadySigned(isAlreadySigned));
                }

                if (signInfo.ShouldSign && peInfo != null)
                {
                    bool isMicrosoftLibrary = ContentUtil.IsMicrosoftLibrary(peInfo.Copyright);
                    bool isMicrosoftCertificate = !ContentUtil.IsThirdPartyCertificate(signInfo.Certificate);
                    if (isMicrosoftLibrary != isMicrosoftCertificate)
                    {
                        string warning;
                        SigningToolErrorCode code;
                        if (isMicrosoftLibrary)
                        {
                            code = SigningToolErrorCode.SIGN001;
                            warning = $"Signing Microsoft library '{file.FullPath}' with 3rd party certificate '{signInfo.Certificate}'. The library is considered Microsoft library due to its copyright: '{peInfo.Copyright}'.";
                        }
                        else
                        {
                            code = SigningToolErrorCode.SIGN004;
                            warning = $"Signing 3rd party library '{file.FullPath}' with Microsoft certificate '{signInfo.Certificate}'. The library is considered 3rd party library due to its copyright: '{peInfo.Copyright}'.";
                        }

                        // https://github.com/dotnet/arcade/issues/10293
                        // Turn the else into a warning (and hoist into the if above) after issue is complete.
                        if (peInfo.IsManaged)
                        {
                            LogWarning(code, warning);
                        }
                        else
                        {
                            _log.LogMessage(MessageImportance.High, $"{code.ToString()}: {warning}");
                        }
                    }
                }

                return new FileWithSignInfo(
                    fileInfo: fileToExamine,
                    signInfo: signInfo,
                    targetFramework: (peInfo != null && peInfo.TargetFramework != "") ? peInfo.TargetFramework : null,
                    hasSignableParts: hasSignableParts);
            }

            if (SignToolConstants.SignableExtensions.Contains(extension) || SignToolConstants.SignableOSXExtensions.Contains(extension))
            {
                // Extract the relative path inside the package / otherwise just return the full path of the file
                LogError(SigningToolErrorCode.SIGN002, signedFileContentKey);
            }
            else
            {
                _log.LogMessage(MessageImportance.Low, $"Ignoring non-signable file: {file.FullPath}");
            }

            return new FileWithSignInfo(fileInfo: fileToExamine, signInfo: SignInfo.Ignore);
        }

        private List<FileInfo> CreateInitialnputList()
        {
            // First, create the initial list of items that will go into the unpack processor
            // Because items with a lower CPID must have their certs determined BEFORE any items with
            // a higher CPID, sort descending, then push onto the stack.

            var filesToProcess = new List<FileInfo>();

            bool? allNullCPIDs = null;

            Dictionary<FileContentKey, FileInfo> _topLevelFileInfos = new Dictionary<FileContentKey, FileInfo>();

            foreach (var itemToSign in _itemsToSign)
            {
                string collisionPriorityId = itemToSign.GetMetadata(SignToolConstants.CollisionPriorityId);
                string fullPath = itemToSign.ItemSpec;
                var contentHash = ContentUtil.GetContentHash(fullPath);
                var fileUniqueKey = new FileContentKey(contentHash, Path.GetFileName(fullPath));
                PathWithHash pathWithHash = new PathWithHash(fullPath, contentHash);

                AddParentContainerMapping(fullPath, fileUniqueKey);

                // If we've seen other CPIDs and one is null, then error
                if (allNullCPIDs.HasValue && string.IsNullOrEmpty(collisionPriorityId) != allNullCPIDs.Value)
                {
                    throw new Exception("All input assets should have all CPIDs, or none should.");
                }

                allNullCPIDs = string.IsNullOrEmpty(collisionPriorityId);

                if (!string.IsNullOrEmpty(collisionPriorityId) && !_topLevelUnpackTasksByCollisionPriorityId.ContainsKey(collisionPriorityId))
                {
                    _topLevelUnpackTasksByCollisionPriorityId.Add(collisionPriorityId, new List<Task>());
                }

                // If there's a wixpack in ItemsToSign which corresponds to this file, pass along the path of 
                // the wixpack so we can associate the wixpack with the item
                var wixPack = _wixPacks.SingleOrDefault(w => w.Moniker.Equals(Path.GetFileName(fullPath), StringComparison.OrdinalIgnoreCase));
                var newFileInfo = new FileInfo(pathWithHash, null, collisionPriorityId, wixPack.FullPath);

                // It's easily possible to have two files with different names but identical contents at the top level. Normally,
                // this would be transparently handled in containers by de-duplication when unpacking, but the top level doesn't
                // run through that. Instead, we keep a list of files to copy at the end.
                if (_topLevelFileInfos.TryGetValue(fileUniqueKey, out FileInfo existingFileInfo))
                {
                    // Copy the signed content to the destination path.
                    _filesToCopy.Add(new KeyValuePair<string, string>(existingFileInfo.File.FullPath, newFileInfo.File.FullPath));
                }
                else
                {
                    _topLevelFileInfos.Add(fileUniqueKey, newFileInfo);
                    filesToProcess.Add(newFileInfo);
                }
            }
            return filesToProcess.OrderBy(f => f.CollisionPriorityId).ToList();
        }

        /// <summary>
        /// Build up the <see cref="ZipData"/> instance for a given zip container. This will also report any consistency
        /// errors found when examining the zip archive.
        /// </summary>
        private async Task<ZipData> TryBuildZipData(FileInfo zipFile, string alternativeArchivePath = null)
        {
            string archivePath = zipFile.File.FullPath;
            if (alternativeArchivePath != null)
            {
                archivePath = alternativeArchivePath;
                Debug.Assert(Path.GetExtension(archivePath) == ".zip");
            }
            else
            {
                Debug.Assert(zipFile.IsZipContainer());
            }

            // Because there is a possibility of 
            using (var archive = new ZipArchive(File.OpenRead(archivePath), ZipArchiveMode.Read))
            {
                var nestedParts = new Dictionary<string, ZipPart>();

                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string relativePath = entry.FullName; // lgtm [cs/zipslip] Archive from trusted source

                    // `entry` might be just a pointer to a folder. We skip those.
                    if (relativePath.EndsWith("/") && entry.Name == "")
                    {
                        continue;
                    }

                    // Before we go any farther, decide whether we need to at all. A file that is
                    // not signable need not be unpacked.
                    if (!FileInfo.IsSignableFile(relativePath))
                    {
                        continue;
                    }

                    using (var entryStream = entry.Open())
                    using (MemoryStream entryMemoryStream = new MemoryStream((int)entry.Length))
                    {
                        // We have to open the file so that we can get at the content hash
                        await entryStream.CopyToAsync(entryMemoryStream);
                        entryMemoryStream.Position = 0;
                        ImmutableArray<byte> contentHash = ContentUtil.GetContentHash(entryMemoryStream);

                        var fileUniqueKey = new FileContentKey(contentHash, Path.GetFileName(relativePath));

                        AddParentContainerMapping(Path.GetFileName(archivePath), fileUniqueKey);

                        var fileName = Path.GetFileName(relativePath);

                        // Determine whether the file has already been extracted
                        string extractPathRoot = fileUniqueKey.StringHash;
                        string tempPath = Path.Combine(_pathToContainerUnpackingDirectory, extractPathRoot, relativePath);

                        // This could race, but only one thread will end up with the OpenWrite
                        // handle. Catch the UnauthorizedAccessException if the file couldn't be written.
                        // We could lock here, but it should be unnecessary.
                        if (!File.Exists(tempPath))
                        {
                            _log.LogMessage($"Extracting file '{fileName}' from '{archivePath}' to '{tempPath}'.");

                            try
                            {
                                Directory.CreateDirectory(Path.GetDirectoryName(tempPath));

                                entryMemoryStream.Position = 0;
                                using (var tempFileStream = File.OpenWrite(tempPath))
                                {
                                    await entryMemoryStream.CopyToAsync(tempFileStream);
                                }
                            }
                            catch (UnauthorizedAccessException e)
                            {
                                _log.LogMessage($"Failed to extract '{fileName}' from '{archivePath}' to '{tempPath}': {e.ToString()}");
                            }
                        }

                        string collisionPriorityId = UpdateCollisionPriorityIdMap(fileUniqueKey, zipFile);

                        // Update the this zip info.
                        PathWithHash nestedFile = new PathWithHash(tempPath, contentHash);

                        var wixPack = _wixPacks.SingleOrDefault(w => w.Moniker.Equals(Path.GetFileName(tempPath), StringComparison.OrdinalIgnoreCase));
                        FileInfo nestedFileInfo = new FileInfo(nestedFile, zipFile.File, collisionPriorityId, wixPack.FullPath);

                        nestedParts.Add(relativePath, new ZipPart(relativePath, nestedFileInfo));
                    }
                }

                return new ZipData(zipFile, nestedParts.ToImmutableDictionary());
            }
        }

        private string UpdateCollisionPriorityIdMap(FileContentKey fileUniqueKey, FileInfo parent)
        {
            // Correctly set the collision priority ID.
            string collisionPriorityId = parent.CollisionPriorityId;
            if (!_hashToCollisionIdMap.TryAdd(fileUniqueKey, collisionPriorityId))
            {
                Debug.Assert(_hashToCollisionIdMap[fileUniqueKey].CompareTo(collisionPriorityId) <= 0);
                collisionPriorityId = _hashToCollisionIdMap[fileUniqueKey];
            }

            return collisionPriorityId;
        }

        /// <summary>
        /// Build up the <see cref="ZipData"/> instance for a given zip container. This will also report any consistency
        /// errors found when examining the zip archive.
        /// </summary>
        private async Task<ZipData> TryBuildWixData(FileInfo msiFileInfo)
        {
            // Treat msi as an archive where the filename is the name of the msi, but its contents are from the corresponding wixpack
            return await TryBuildZipData(msiFileInfo, msiFileInfo.WixContentFilePath);
        }

        // Input files are in order of collisionPriId. To ensure correctness,
        // we MUST compute signing info for all lower collision ids's before higher ones begin.
        // The reason is that the signing info for lower IDs dominates those of higher IDs.
        // An artifact that shows up in two nupkgs comes is assumed to come from the one with the lower
        // ID (if one is lower), and thus the signing info associated with that ID takes precedence.

        // By convention, we must have started the sig computation for all 
        // task.whenall

        // THe problem here is that, let's say you have two input files to process.
        // The first is from CID=0, the second from 1.
        // If you Task.Parallel you absolutely could process the second before the first. So you need to wait on the first,
        // but you ONLY need to wait on the unpack/compute sig parts. You can absolutely race ahead otherwise.
        // This is non-trivial to implement because you don't have an easy thing to wait on. You haven't started the unpack task of the first
        // container. So you are left to implement some kind of wait loop there. While the algorithm MIGHT be cleaner...I'm not sure how
        // to do this.
        // There are potentially other ways of solving this. You could use the algo as specified, but backtrack if the key changes.
        // But no, that sucks because you have to backtrack an arbitrary number of spaces.
        //
        // In the other, stack based method, you might be able to solve this problem with another stack.
        // You have a:
        // - Unpack stack
        // - Computation stack
        // - Sign stack
        // - Repack stack
        //
        // In this method, the computation stack processing must stop if the CPID of the file in any new files **could**
        // be introduced into the CPID stack that are of lower ID. So basically, all unpacking of lower IDs must be done.
        // This gets tough? You could implement a wait until all unpack/computation is done. OR, you could say that collisions
        // are quite rare. When you find a CPID for a file that is lower (like the original algo did), you recompute, then re-add the
        // parent to the pack list if already packed, etc.? Tough for sure. I don't know how you deal with that and parallelism.
        // What if it's not packed but on the list? That means the first computation would be wrong, the submit signing....Or you could eve
        // have the case where the first and second are next to each other in the queue and they process in parallel. bad.
        // Maybe the right thing IS to just do a wait for all top-level unpack and computation in CPID's < current to be done. Because
        // files are processed mostly sequentually, I think you'd end up with minimal wait time without the async await difficulties.
        // I suppose the Q is how do you know when unpack compute is done? You do a bag (or just a ref count) per CPID and every time
        // you pull a new top level item off the list you increment the ref count.

        private void AddParentContainerMapping(string fullPath, FileContentKey fileUniqueKey)
        {
            if (!_parentContainerMapping.TryGetValue(fileUniqueKey, out var packages))
            {
                packages = new HashSet<string>();
            }

            packages.Add(fullPath);

            _parentContainerMapping[fileUniqueKey] = packages;
        }

        #region Logging

        private void LogWarning(SigningToolErrorCode code, string message)
            => _log.LogWarning(subcategory: null, warningCode: code.ToString(), helpKeyword: null, file: null, lineNumber: 0, columnNumber: 0, endLineNumber: 0, endColumnNumber: 0, message: message);

        private void LogError(SigningToolErrorCode code, FileContentKey targetFile)
        {
            if (!_errors.TryGetValue(code, out var filesErrored))
            {
                filesErrored = new HashSet<FileContentKey>();
            }

            filesErrored.Add(targetFile);
            _errors[code] = filesErrored;
        }

        #endregion
    }
}
