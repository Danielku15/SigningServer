/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2018 Daniel Kuschny (C# port based on oreo-master)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SigningServer.Android.Apk;
using SigningServer.Android.Crypto;
using SigningServer.Android.Util;

namespace SigningServer.Android
{
    /// <summary>
    /// Default implementation of ApkSignerEngine
    /// </summary>
    /// <remarks>
    /// IMPLEMENTATION NOTE: This engine generates a signed APK as follows:
    /// 1. The engine asks its client to output input JAR entries which are not part of JAR
    ///    signature.
    /// 2. If JAR signing (v1 signing) is enabled, the engine inspects the output JAR entries to
    ///    compute their digests, to be placed into output META-INF/MANIFEST.MF. It also inspects
    ///    the contents of input and output META-INF/MANIFEST.MF to borrow the main section of the
    ///    file. It does not care about individual (i.e., JAR entry-specific) sections. It then
    ///    emits the v1 signature (a set of JAR entries) and asks the client to output them.
    /// 3. If APK Signature Scheme v2 (v2 signing) is enabled, the engine emits an APK Signing Block
    ///    from outputZipSections() and asks its client to insert this block into the output.
    /// </remarks>
    public class DefaultApkSignerEngine
    {
        private readonly bool _v1SigningEnabled;
        private readonly bool _v2SigningEnabled;

        private readonly DigestAlgorithm _v1ContentDigestAlgorithm;
        private readonly ISet<string> _signatureExpectedOutputJarEntryNames;

        private GetJarEntryDataRequest _inputJarManifestEntryDataRequest;
        private readonly IDictionary<string, byte[]> _emittedSignatureJarEntryData = new Dictionary<string, byte[]>();

        private readonly IDictionary<string, GetJarEntryDataRequest> _outputSignatureJarEntryDataRequests = new Dictionary<string, GetJarEntryDataRequest>();
        private readonly IDictionary<string, GetJarEntryDataDigestRequest> _outputJarEntryDigestRequests = new Dictionary<string, GetJarEntryDataDigestRequest>();

        private readonly IDictionary<string, byte[]> _outputJarEntryDigests = new Dictionary<string, byte[]>();

        private OutputApkSigningBlockRequestImpl _addV2SignatureRequest;
        private OutputJarSignatureRequestImpl _addV1SignatureRequest;

        private bool _v1SignaturePending;
        private bool _v2SignaturePending;
        private readonly V1SchemeSigner.SignerConfig _v1SignerConfigs;
        private readonly V2SchemeSigner.SignerConfig _v2SignerConfigs;

        /// <summary>
        /// Indicates to this engine that the input APK contains the provided APK Signing Block. The
        /// block may contain signatures of the input APK, such as APK Signature Scheme v2 signatures.
        /// </summary>
        /// <param name="apkSigningBlock"></param>
        public void InputApkSigningBlock(DataSource apkSigningBlock)
        {
            // TODO: Preserve blocks other than APK Signature Scheme v2 blocks.
        }

        /// <summary>
        /// Indicates to this engine that all JAR entries have been output.
        /// </summary>
        /// <returns>
        /// request to add JAR signature to the output or <code>null</code> if there is no need to add
        /// a JAR signature.The request will contain additional JAR entries to be output.The
        /// request must be fulfilled before <see cref="OutputZipSections"/> is invoked.
        /// </returns>
        public IOutputJarSignatureRequest OutputJarEntries()
        {
            if (!_v1SignaturePending)
            {
                return null;
            }
            if ((_inputJarManifestEntryDataRequest != null)
                    && (!_inputJarManifestEntryDataRequest.IsDone))
            {
                throw new InvalidOperationException(
                        "Still waiting to inspect input APK's "
                                + _inputJarManifestEntryDataRequest.EntryName);
            }
            foreach (var digestRequest in _outputJarEntryDigestRequests.Values)
            {
                var entryName = digestRequest.EntryName;
                if (!digestRequest.IsDone)
                {
                    throw new InvalidOperationException(
                            "Still waiting to inspect output APK's " + entryName);
                }
                _outputJarEntryDigests.Add(entryName, digestRequest.Digest);
            }
            _outputJarEntryDigestRequests.Clear();
            foreach (var dataRequest in _outputSignatureJarEntryDataRequests.Values)
            {
                if (!dataRequest.IsDone)
                {
                    throw new InvalidOperationException(
                            "Still waiting to inspect output APK's " + dataRequest.EntryName);
                }
            }

            IList<int> apkSigningSchemeIds = new List<int>();
            if (_v2SigningEnabled)
            {
                apkSigningSchemeIds.Add(2);
            }
            var inputJarManifest =
                    (_inputJarManifestEntryDataRequest != null)
                        ? _inputJarManifestEntryDataRequest.Data : null;
            // Check whether the most recently used signature (if present) is still fine.
            List<Tuple<string, byte[]>> signatureZipEntries;
            if ((_addV1SignatureRequest == null) || (!_addV1SignatureRequest.IsDone))
            {
                try
                {
                    signatureZipEntries =
                            V1SchemeSigner.Sign(
                                    _v1SignerConfigs,
                                    _v1ContentDigestAlgorithm,
                                    _outputJarEntryDigests,
                                    apkSigningSchemeIds,
                                    inputJarManifest);
                }
                catch (CryptographicException e)
                {
                    throw new CryptographicException("Failed to generate v1 signature", e);
                }
            }
            else
            {
                var newManifest = V1SchemeSigner.GenerateManifestFile(_v1ContentDigestAlgorithm, _outputJarEntryDigests, inputJarManifest);
                var emittedSignatureManifest = _emittedSignatureJarEntryData[V1SchemeSigner.ManifestEntryName];
                if (!newManifest.Contents.SequenceEqual(emittedSignatureManifest))
                {
                    // Emitted v1 signature is no longer valid.
                    try
                    {
                        signatureZipEntries =
                                V1SchemeSigner.SignManifest(
                                        _v1SignerConfigs,
                                        _v1ContentDigestAlgorithm,
                                        apkSigningSchemeIds,
                                        newManifest);
                    }
                    catch (CryptographicException e)
                    {
                        throw new CryptographicException("Failed to generate v1 signature", e);
                    }
                }
                else
                {
                    // Emitted v1 signature is still valid. Check whether the signature is there in the
                    // output.
                    signatureZipEntries = new List<Tuple<string, byte[]>>();
                    foreach (var expectedOutputEntry in _emittedSignatureJarEntryData)
                    {
                        var entryName = expectedOutputEntry.Key;
                        var expectedData = expectedOutputEntry.Value;
                        var actualDataRequest =
                                _outputSignatureJarEntryDataRequests[entryName];
                        if (actualDataRequest == null)
                        {
                            // This signature entry hasn't been output.
                            signatureZipEntries.Add(Tuple.Create(entryName, expectedData));
                            continue;
                        }
                        var actualData = actualDataRequest.Data;
                        if (!expectedData.SequenceEqual(actualData))
                        {
                            signatureZipEntries.Add(Tuple.Create(entryName, expectedData));
                        }
                    }
                    if (signatureZipEntries.Count == 0)
                    {
                        // v1 signature in the output is valid
                        return null;
                    }
                    // v1 signature in the output is not valid.
                }
            }
            if (signatureZipEntries.Count == 0)
            {
                // v1 signature in the output is valid
                _v1SignaturePending = false;
                return null;
            }
            var sigEntries = new List<JarEntry>(signatureZipEntries.Count());
            foreach (var entry in signatureZipEntries)
            {
                var entryName = entry.Item1;
                var entryData = entry.Item2;
                sigEntries.Add(new JarEntry(entryName, entryData));
                _emittedSignatureJarEntryData.Add(entryName, entryData);
            }
            _addV1SignatureRequest = new OutputJarSignatureRequestImpl(sigEntries);
            return _addV1SignatureRequest;
        }

        public DefaultApkSignerEngine(X509Certificate2 certificate, int minSdkVersion, bool v1SigningEnabled,
            bool v2SigningEnabled, DigestAlgorithm digestAlgorithm)
        {
            _v1SigningEnabled = v1SigningEnabled;
            _v2SigningEnabled = v2SigningEnabled;
            _v1SignaturePending = v1SigningEnabled;
            _v2SignaturePending = v2SigningEnabled;

            if (v1SigningEnabled)
            {
                var v1SignerName = V1SchemeSigner.GetSafeSignerName(certificate.FriendlyName);
                // Check whether the signer's name is unique among all v1 signers
                var v1SignatureDigestAlgorithm = digestAlgorithm ??
                    V1SchemeSigner.GetSuggestedSignatureDigestAlgorithm(
                        certificate.PublicKey, minSdkVersion);
                var v1SignerConfig = new V1SchemeSigner.SignerConfig();
                v1SignerConfig.Name = v1SignerName;
                v1SignerConfig.Certificate = certificate;
                v1SignerConfig.SignatureDigestAlgorithm = v1SignatureDigestAlgorithm;

                _v1SignerConfigs = v1SignerConfig;
                _v1ContentDigestAlgorithm = v1SignatureDigestAlgorithm;
                _signatureExpectedOutputJarEntryNames = V1SchemeSigner.GetOutputEntryNames(_v1SignerConfigs, minSdkVersion);

                _v1ContentDigestAlgorithm = V1SchemeSigner.GetSuggestedSignatureDigestAlgorithm(certificate.PublicKey, minSdkVersion);

            }

            if (v2SigningEnabled)
            {
                var v2SignerConfig = new V2SchemeSigner.SignerConfig();
                v2SignerConfig.Certificates = certificate;
                v2SignerConfig.SignatureAlgorithm = V2SchemeSigner.GetSuggestedSignatureAlgorithms(certificate.PublicKey, minSdkVersion, digestAlgorithm);
                _v2SignerConfigs = v2SignerConfig;
            }
        }

        /// <summary>
        /// Indicates to this engine that the specified JAR entry was encountered in the input APK.
        /// </summary>
        /// <param name="entryName"></param>
        /// <returns>instructions about how to proceed with this entry</returns>
        public InputJarEntryInstructions InputJarEntry(string entryName)
        {
            var outputPolicy = GetInputJarEntryOutputPolicy(entryName);
            switch (outputPolicy)
            {
                case OutputPolicy.Skip:
                    return new InputJarEntryInstructions(OutputPolicy.Skip);
                case OutputPolicy.Output:
                    return new InputJarEntryInstructions(OutputPolicy.Output);
                case OutputPolicy.OutputByEngine:
                    if (V1SchemeSigner.ManifestEntryName.Equals(entryName))
                    {
                        // We copy the main section of the JAR manifest from input to output. Thus, this
                        // invalidates v1 signature and we need to see the entry's data.
                        _inputJarManifestEntryDataRequest = new GetJarEntryDataRequest(entryName);
                        return new InputJarEntryInstructions(OutputPolicy.OutputByEngine, _inputJarManifestEntryDataRequest);
                    }
                    return new InputJarEntryInstructions(OutputPolicy.OutputByEngine);
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        /// <summary>
        /// Returns the output policy for the provided input JAR entry.
        /// </summary>
        /// <param name="entryName"></param>
        /// <returns></returns>
        private OutputPolicy GetInputJarEntryOutputPolicy(string entryName)
        {
            if (_signatureExpectedOutputJarEntryNames.Contains(entryName))
            {
                return OutputPolicy.OutputByEngine;
            }
            if (V1SchemeSigner.IsJarEntryDigestNeededInManifest(entryName))
            {
                return OutputPolicy.Output;
            }
            return OutputPolicy.Skip;
        }

        /// <summary>
        /// Indicates to this engine that the specified JAR entry was output.
        ///
        /// It is unnecessary to invoke this method for entries added to output by this engine (e.g.,
        /// requested by <see cref="OutputJarEntries"/> provided the entries were output with exactly the
        /// data requested by the engine.
        /// </summary>
        /// <param name="entryName"></param>
        /// <returns>
        /// request to inspect the entry or <code>null</code> if the engine does not need to inspect
        /// the entry.The request must be fulfilled before<see cref="OutputJarEntries"/> is invoked.
        /// </returns>
        public IInspectJarEntryRequest OutputJarEntry(string entryName)
        {
            InvalidateV2Signature();

            if (!_v1SigningEnabled)
            {
                // No need to inspect JAR entries when v1 signing is not enabled.
                return null;
            }


            // v1 signing is enabled
            if (V1SchemeSigner.IsJarEntryDigestNeededInManifest(entryName))
            {
                // This entry is covered by v1 signature. We thus need to inspect the entry's data to
                // compute its digest(s) for v1 signature.
                // TODO: Handle the case where other signer's v1 signatures are present and need to be
                // preserved. In that scenario we can't modify MANIFEST.MF and add/remove JAR entries
                // covered by v1 signature.
                InvalidateV1Signature();
                var dataDigestRequest = new GetJarEntryDataDigestRequest(entryName, _v1ContentDigestAlgorithm);
                _outputJarEntryDigestRequests.Add(entryName, dataDigestRequest);
                _outputJarEntryDigests.Remove(entryName);
                return dataDigestRequest;
            }
            if (_signatureExpectedOutputJarEntryNames.Contains(entryName))
            {
                // This entry is part of v1 signature generated by this engine. We need to check whether
                // the entry's data is as output by the engine.
                InvalidateV1Signature();
                GetJarEntryDataRequest dataRequest;
                if (V1SchemeSigner.ManifestEntryName.Equals(entryName))
                {
                    dataRequest = new GetJarEntryDataRequest(entryName);
                    _inputJarManifestEntryDataRequest = dataRequest;
                }
                else
                {
                    // If this entry is part of v1 signature which has been emitted by this engine,
                    // check whether the output entry's data matches what the engine emitted.
                    dataRequest = (_emittedSignatureJarEntryData.ContainsKey(entryName))
                                    ? new GetJarEntryDataRequest(entryName) : null;
                }
                if (dataRequest != null)
                {
                    _outputSignatureJarEntryDataRequests.Add(entryName, dataRequest);
                }
                return dataRequest;
            }
            // This entry is not covered by v1 signature and isn't part of v1 signature.
            return null;
        }

        /// <summary>
        /// Indicates to this engine that the ZIP sections comprising the output APK have been output.
        ///
        /// The provided data sources are guaranteed to not be used by the engine after this method terminates.
        /// </summary>
        /// <param name="zipEntries">the section of ZIP archive containing Local File Header records and data of
        /// the ZIP entries.In a well-formed archive, this section starts at the start of the
        /// archive and extends all the way to the ZIP Central Directory.
        /// </param>
        /// <param name="zipCentralDirectory">ZIP Central Directory section</param>
        /// <param name="zipEocd">ZIP End of Central Directory (EoCD) record
        /// </param>
        /// <returns>
        /// request to add an APK Signing Block to the output or {@code null} if the output must
        /// not contain an APK Signing Block.The request must be fulfilled before <see cref="OutputDone"/> is invoked.
        /// </returns>
        public IOutputApkSigningBlockRequest OutputZipSections(Stream zipEntries, Stream zipCentralDirectory, Stream zipEocd)
        {
            CheckV1SigningDoneIfEnabled();
            if (!_v2SigningEnabled)
            {
                return null;
            }

            InvalidateV2Signature();
            var apkSigningBlock = V2SchemeSigner.GenerateApkSigningBlock(zipEntries, zipCentralDirectory, zipEocd, _v2SignerConfigs);

            _addV2SignatureRequest = new OutputApkSigningBlockRequestImpl(apkSigningBlock);
            return _addV2SignatureRequest;
        }

        /// <summary>
        /// Indicates to this engine that the signed APK was output.
        /// This does not change the output APK. The method helps the client confirm that the current
        /// output is signed.
        /// </summary>
        public void OutputDone()
        {
            CheckV1SigningDoneIfEnabled();
            CheckV2SigningDoneIfEnabled();
        }

        private void InvalidateV2Signature()
        {
            if (_v2SigningEnabled)
            {
                _v2SignaturePending = true;
                _addV2SignatureRequest = null;
            }
        }
        private void InvalidateV1Signature()
        {
            if (_v1SigningEnabled)
            {
                _v1SignaturePending = true;
            }
            InvalidateV2Signature();
        }

        private void CheckV1SigningDoneIfEnabled()
        {
            if (!_v1SignaturePending)
            {
                return;
            }
            if (_addV1SignatureRequest == null)
            {
                throw new InvalidOperationException("v1 signature (JAR signature) not yet generated. Skipped outputJarEntries()?");
            }
            if (!_addV1SignatureRequest.IsDone)
            {
                throw new InvalidOperationException(
                    "v1 signature (JAR signature) addition requested by outputJarEntries() hasn't"
                    + " been fulfilled");
            }
            foreach (var expectedOutputEntry in _emittedSignatureJarEntryData)
            {
                var entryName = expectedOutputEntry.Key;
                var expectedData = expectedOutputEntry.Value;
                var actualDataRequest = _outputSignatureJarEntryDataRequests[entryName];
                if (actualDataRequest == null)
                {
                    throw new InvalidOperationException(
                        "APK entry " + entryName + " not yet output despite this having been"
                        + " requested");
                }
                else if (!actualDataRequest.IsDone)
                {
                    throw new InvalidOperationException(
                        "Still waiting to inspect output APK's " + entryName);
                }
                var actualData = actualDataRequest.Data;
                if (!expectedData.SequenceEqual(actualData))
                {
                    throw new InvalidOperationException(
                        "Output APK entry " + entryName + " data differs from what was requested");
                }
            }
            _v1SignaturePending = false;
        }

        private void CheckV2SigningDoneIfEnabled()
        {
            if (!_v2SignaturePending)
            {
                return;
            }
            if (_addV2SignatureRequest == null)
            {
                throw new InvalidOperationException(
                    "v2 signature (APK Signature Scheme v2 signature) not yet generated."
                    + " Skipped outputZipSections()?");
            }
            if (!_addV2SignatureRequest.IsDone)
            {
                throw new InvalidOperationException(
                    "v2 signature (APK Signature Scheme v2 signature) addition requested by"
                    + " outputZipSections() hasn't been fulfilled yet");
            }
            _addV2SignatureRequest = null;
            _v2SignaturePending = false;
        }

        #region Nested Types

        private class OutputJarSignatureRequestImpl : IOutputJarSignatureRequest
        {
            private readonly IList<JarEntry> _additionalJarEntries;
            private volatile bool _done;

            public OutputJarSignatureRequestImpl(List<JarEntry> additionalZipEntries)
            {
                _additionalJarEntries = additionalZipEntries.AsReadOnly();
            }

            public IList<JarEntry> AdditionalJarEntries => _additionalJarEntries;
            public void Done()
            {
                _done = true;
            }

            public bool IsDone => _done;
        }


        private class OutputApkSigningBlockRequestImpl : IOutputApkSigningBlockRequest
        {
            private readonly byte[] _apkSigningBlock;
            private volatile bool _done;

            public OutputApkSigningBlockRequestImpl(byte[] apkSigingBlock)
            {
                _apkSigningBlock = (byte[])apkSigingBlock.Clone();
            }
            public byte[] ApkSigningBlock
            {
                get { return (byte[])_apkSigningBlock.Clone(); }
            }
            public void Done()
            {
                _done = true;
            }

            public bool IsDone => _done;
        }


        private class GetJarEntryDataDigestRequest : IInspectJarEntryRequest
        {
            private readonly object _lock = new object();

            private readonly DigestAlgorithm _jcaDigestAlgorithm;
            private MessageDigestStream _dataSink;
            private HashAlgorithm _messageDigest;
            private bool _done;
            private byte[] _digest;
            public string EntryName { get; }

            public GetJarEntryDataDigestRequest(string entryName, DigestAlgorithm jcaDigestAlgorithm)
            {
                _jcaDigestAlgorithm = jcaDigestAlgorithm;
                EntryName = entryName;
            }

            public Stream DataSink
            {
                get
                {
                    lock (_lock)
                    {
                        CheckNotDone();
                        if (_dataSink == null)
                        {
                            _dataSink = new MessageDigestStream(new[] { MessageDigest });
                        }
                        return _dataSink;
                    }
                }
            }

            private HashAlgorithm MessageDigest
            {
                get
                {
                    lock (_lock)
                    {
                        if (_messageDigest == null)
                        {
                            _messageDigest = _jcaDigestAlgorithm.CreateInstance();
                            if (_messageDigest == null)
                            {
                                throw new Exception(_jcaDigestAlgorithm + " MessageDigest not available");
                            }
                        }
                        return _messageDigest;
                    }
                }
            }

            public void Done()
            {
                lock (_lock)
                {
                    if (_done)
                    {
                        return;
                    }
                    _done = true;
                    _messageDigest.TransformFinalBlock(new byte[0], 0, 0);
                    _digest = _messageDigest.Hash;
                    _messageDigest.Dispose();
                    _messageDigest = null;
                    _dataSink = null;
                }
            }
            public bool IsDone
            {
                get
                {
                    lock (_lock)
                    {
                        return _done;
                    }
                }
            }
            private void CheckNotDone()
            {
                lock (_lock)
                {
                    if (_done)
                    {
                        throw new InvalidOperationException("Already done");
                    }
                }
            }

            public byte[] Digest
            {
                get
                {
                    lock (_lock)
                    {
                        if (!_done)
                        {
                            throw new InvalidOperationException("Not yet done");
                        }
                        return (byte[])_digest.Clone();
                    }
                }
            }
        }

        private class GetJarEntryDataRequest : IInspectJarEntryRequest
        {
            private readonly object _lock = new object();
            private MemoryStream _dataSinkBuf;
            private bool _done;
            public string EntryName { get; }

            public GetJarEntryDataRequest(string entryName)
            {
                EntryName = entryName;
            }

            public Stream DataSink
            {
                get
                {
                    lock (_lock)
                    {
                        CheckNotDone();
                        if (_dataSinkBuf == null)
                        {
                            _dataSinkBuf = new MemoryStream();
                        }

                        return _dataSinkBuf;
                    }
                }
            }

            public void Done()
            {
                lock (_lock)
                {
                    if (_done)
                    {
                        return;
                    }
                    _done = true;
                }
            }

            public bool IsDone
            {
                get
                {
                    lock (_lock)
                    {
                        return _done;
                    }
                }
            }

            private void CheckNotDone()
            {
                lock (_lock)
                {
                    if (_done)
                    {
                        throw new InvalidOperationException("Already done");
                    }
                }
            }

            public byte[] Data
            {
                get
                {
                    lock (_lock)
                    {
                        if (!_done)
                        {
                            throw new InvalidOperationException("Not yet done");
                        }

                        return _dataSinkBuf.ToArray();
                    }
                }
            }
        }


        public class InputJarEntryInstructions
        {
            public OutputPolicy OutputPolicy { get; }
            public IInspectJarEntryRequest InspectJarEntryRequest { get; }

            public InputJarEntryInstructions(OutputPolicy outputPolicy)
              : this(outputPolicy, null)
            {
            }

            public InputJarEntryInstructions(
                OutputPolicy outputPolicy,
                IInspectJarEntryRequest inspectJarEntryRequest)
            {
                OutputPolicy = outputPolicy;
                InspectJarEntryRequest = inspectJarEntryRequest;
            }
        }


        /**
         * Output policy for an input APK's JAR entry.
         */
        public enum OutputPolicy
        {
            /** Entry must not be output. */
            Skip,
            /** Entry should be output. */
            Output,
            /** Entry will be output by the engine. The client can thus ignore this input entry. */
            OutputByEngine,
        }

        public interface IInspectJarEntryRequest
        {
            /**
             * Returns the data sink into which the entry's uncompressed data should be sent.
             */
            Stream DataSink { get; }
            /**
             * Indicates that entry's data has been provided in full.
             */
            void Done();
            /**
             * Returns the name of the JAR entry.
             */
            string EntryName { get; }
        }


        public interface IOutputJarSignatureRequest
        {
            /**
             * Returns JAR entries that must be added to the output APK.
             */
            IList<JarEntry> AdditionalJarEntries { get; }
            /**
             * Indicates that the JAR entries contained in this request were added to the output APK.
             */
            void Done();
        }


        public class JarEntry
        {
            private readonly byte[] _data;
            public string Name { get; }
            public byte[] Data => (byte[])_data.Clone();

            public JarEntry(string name, byte[] data)
            {
                Name = name;
                _data = data;
            }
        }
        public interface IOutputApkSigningBlockRequest
        {
            /**
             * Returns the APK Signing Block.
             */
            byte[] ApkSigningBlock { get; }
            /**
             * Indicates that the APK Signing Block was output as requested.
             */
            void Done();
        }

        #endregion
    }
}
