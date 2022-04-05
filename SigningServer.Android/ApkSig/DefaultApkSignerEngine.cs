﻿/*
 * Copyright (C) 2016 The Android Open Source Project
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
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Policy;
using SigningServer.Android;
using SigningServer.Android.ApkSig;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.Stamp;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Android.ApkSig.Internal.Apk.v2;
using SigningServer.Android.ApkSig.Internal.Apk.v3;
using SigningServer.Android.ApkSig.Internal.Apk.v4;
using SigningServer.Android.ApkSig.Internal.Jar;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig
{
    /**
     * Default implementation of {@link ApkSignerEngine}.
     *
     * <p>Use {@link Builder} to obtain instances of this engine.
     */
    public class DefaultApkSignerEngine : ApkSignerEngine
    {
        // IMPLEMENTATION NOTE: This engine generates a signed APK as follows:
        // 1. The engine asks its client to output input JAR entries which are not part of JAR
        //    signature.
        // 2. If JAR signing (v1 signing) is enabled, the engine inspects the output JAR entries to
        //    compute their digests, to be placed into output META-INF/MANIFEST.MF. It also inspects
        //    the contents of input and output META-INF/MANIFEST.MF to borrow the main section of the
        //    file. It does not care about individual (i.e., JAR entry-specific) sections. It then
        //    emits the v1 signature (a set of JAR entries) and asks the client to output them.
        // 3. If APK Signature Scheme v2 (v2 signing) is enabled, the engine emits an APK Signing Block
        //    from outputZipSections() and asks its client to insert this block into the output.
        // 4. If APK Signature Scheme v3 (v3 signing) is enabled, the engine includes it in the APK
        //    Signing BLock output from outputZipSections() and asks its client to insert this block
        //    into the output.  If both v2 and v3 signing is enabled, they are both added to the APK
        //    Signing Block before asking the client to insert it into the output.

        private readonly bool mV1SigningEnabled;
        private readonly bool mV2SigningEnabled;
        private readonly bool mV3SigningEnabled;
        private readonly bool mVerityEnabled;
        private readonly bool mDebuggableApkPermitted;
        private readonly bool mOtherSignersSignaturesPreserved;
        private readonly String mCreatedBy;
        private readonly List<SignerConfig> mSignerConfigs;
        private readonly SignerConfig mSourceStampSignerConfig;
        private readonly SigningCertificateLineage mSourceStampSigningCertificateLineage;
        private readonly int mMinSdkVersion;
        private readonly SigningCertificateLineage mSigningCertificateLineage;

        private List<byte[]> mPreservedV2Signers = new List<byte[]>();
        private List<Tuple<byte[], int>> mPreservedSignatureBlocks = new List<Tuple<byte[], int>>();

        private List<V1SchemeSigner.SignerConfig> mV1SignerConfigs = new List<V1SchemeSigner.SignerConfig>();
        private DigestAlgorithm mV1ContentDigestAlgorithm;

        private bool mClosed;

        private bool mV1SignaturePending;

        /** Names of JAR entries which this engine is expected to output as part of v1 signing. */
        private ISet<String> mSignatureExpectedOutputJarEntryNames = new HashSet<string>();

        /** Requests for digests of output JAR entries. */
        private readonly Dictionary<String, GetJarEntryDataDigestRequest> mOutputJarEntryDigestRequests =
            new Dictionary<string, GetJarEntryDataDigestRequest>();

        /** Digests of output JAR entries. */
        private readonly Dictionary<String, byte[]> mOutputJarEntryDigests = new Dictionary<string, byte[]>();

        /** Data of JAR entries emitted by this engine as v1 signature. */
        private readonly Dictionary<String, byte[]> mEmittedSignatureJarEntryData = new Dictionary<string, byte[]>();

        /** Requests for data of output JAR entries which comprise the v1 signature. */
        private readonly Dictionary<String, GetJarEntryDataRequest> mOutputSignatureJarEntryDataRequests =
            new Dictionary<string, GetJarEntryDataRequest>();

        /**
     * Request to obtain the data of MANIFEST.MF or {@code null} if the request hasn't been issued.
     */
        private GetJarEntryDataRequest mInputJarManifestEntryDataRequest;

        /**
     * Request to obtain the data of AndroidManifest.xml or {@code null} if the request hasn't been
     * issued.
     */
        private GetJarEntryDataRequest mOutputAndroidManifestEntryDataRequest;

        /**
     * Whether the package being signed is marked as {@code android:debuggable} or {@code null} if
     * this is not yet known.
     */
        private bool? mDebuggable;

        /**
     * Request to output the emitted v1 signature or {@code null} if the request hasn't been issued.
     */
        private OutputJarSignatureRequestImpl mAddV1SignatureRequest;

        private bool mV2SignaturePending;
        private bool mV3SignaturePending;

        /**
     * Request to output the emitted v2 and/or v3 signature(s) {@code null} if the request hasn't
     * been issued.
     */
        private OutputApkSigningBlockRequestImpl mAddSigningBlockRequest;

        private RunnablesExecutor mExecutor = RunnablesExecutors.MULTI_THREADED;

        /**
     * A Set of block IDs to be discarded when requesting to preserve the original signatures.
     */
        private static readonly ISet<int> DISCARDED_SIGNATURE_BLOCK_IDS = new HashSet<int>
        {
            // The verity padding block is recomputed on an
            // ApkSigningBlockUtils.ANDROID_COMMON_PAGE_ALIGNMENT_BYTES boundary.
            ApkSigningBlockUtils.VERITY_PADDING_BLOCK_ID,
            // The source stamp block is not currently preserved; appending a new signature scheme
            // block will invalidate the previous source stamp.
            Constants.V1_SOURCE_STAMP_BLOCK_ID,
            Constants.V2_SOURCE_STAMP_BLOCK_ID
        };

        private DefaultApkSignerEngine(List<SignerConfig> signerConfigs,
            SignerConfig sourceStampSignerConfig,
            SigningCertificateLineage sourceStampSigningCertificateLineage,
            int minSdkVersion,
            bool v1SigningEnabled,
            bool v2SigningEnabled,
            bool v3SigningEnabled,
            bool verityEnabled,
            bool debuggableApkPermitted,
            bool otherSignersSignaturesPreserved,
            string createdBy,
            SigningCertificateLineage signingCertificateLineage, 
            DigestAlgorithm digestAlgorithm)

        {
            if (signerConfigs.Count == 0)
            {
                throw new ArgumentException("At least one signer config must be provided");
            }

            mV1SigningEnabled = v1SigningEnabled;
            mV2SigningEnabled = v2SigningEnabled;
            mV3SigningEnabled = v3SigningEnabled;
            mVerityEnabled = verityEnabled;
            mV1SignaturePending = v1SigningEnabled;
            mV2SignaturePending = v2SigningEnabled;
            mV3SignaturePending = v3SigningEnabled;
            mDebuggableApkPermitted = debuggableApkPermitted;
            mOtherSignersSignaturesPreserved = otherSignersSignaturesPreserved;
            mCreatedBy = createdBy;
            mSignerConfigs = signerConfigs;
            mSourceStampSignerConfig = sourceStampSignerConfig;
            mSourceStampSigningCertificateLineage = sourceStampSigningCertificateLineage;
            mMinSdkVersion = minSdkVersion;
            mSigningCertificateLineage = signingCertificateLineage;

            if (v1SigningEnabled)
            {
                if (v3SigningEnabled)
                {
                    // v3 signing only supports single signers, of which the oldest (first) will be the
                    // one to use for v1 and v2 signing
                    SignerConfig oldestConfig = signerConfigs[0];

                    // in the event of signing certificate changes, make sure we have the oldest in the
                    // signing history to sign with v1
                    if (signingCertificateLineage != null)
                    {
                        SigningCertificateLineage subLineage =
                            signingCertificateLineage.getSubLineage(
                                oldestConfig.mCertificates[0]);
                        if (subLineage.size() != 1)
                        {
                            throw new ArgumentException(
                                "v1 signing enabled but the oldest signer in the"
                                + " SigningCertificateLineage is missing.  Please provide the"
                                + " oldest signer to enable v1 signing");
                        }
                    }

                    createV1SignerConfigs(new List<SignerConfig>
                    {
                        oldestConfig
                    }, minSdkVersion, digestAlgorithm);
                }
                else
                {
                    createV1SignerConfigs(signerConfigs, minSdkVersion, digestAlgorithm);
                }
            }
        }

        private void createV1SignerConfigs(List<SignerConfig> signerConfigs, int minSdkVersion,
            DigestAlgorithm digestAlgorithm)
        {
            mV1SignerConfigs = new List<V1SchemeSigner.SignerConfig>(signerConfigs.Count);
            Dictionary<String, int?> v1SignerNameToSignerIndex = new Dictionary<String, int?>(signerConfigs.Count);
            for (int i = 0; i < signerConfigs.Count; i++)
            {
                SignerConfig signerConfig = signerConfigs[i];
                List<X509Certificate> certificates = signerConfig.getCertificates();
                PublicKey publicKey = certificates[0].getPublicKey();

                String v1SignerName = V1SchemeSigner.getSafeSignerName(signerConfig.getName());
                // Check whether the signer's name is unique among all v1 signers
                v1SignerNameToSignerIndex.TryGetValue(v1SignerName, out var indexOfOtherSignerWithSameName);
                if (indexOfOtherSignerWithSameName != null)
                {
                    throw new ArgumentException(
                        "Signers #"
                        + (indexOfOtherSignerWithSameName + 1)
                        + " and #"
                        + (i + 1)
                        + " have the same name: "
                        + v1SignerName
                        + ". v1 signer names must be unique");
                }

                v1SignerNameToSignerIndex.Add(v1SignerName, i);

                DigestAlgorithm v1SignatureDigestAlgorithm =
                    V1SchemeSigner.getSuggestedSignatureDigestAlgorithm(publicKey, minSdkVersion);
                V1SchemeSigner.SignerConfig v1SignerConfig = new V1SchemeSigner.SignerConfig();
                v1SignerConfig.name = v1SignerName;
                v1SignerConfig.privateKey = signerConfig.getPrivateKey();
                v1SignerConfig.certificates = certificates;
                v1SignerConfig.signatureDigestAlgorithm = v1SignatureDigestAlgorithm;
                v1SignerConfig.deterministicDsaSigning = signerConfig.getDeterministicDsaSigning();
                // For digesting contents of APK entries and of MANIFEST.MF, pick the algorithm
                // of comparable strength to the digest algorithm used for computing the signature.
                // When there are multiple signers, pick the strongest digest algorithm out of their
                // signature digest algorithms. This avoids reducing the digest strength used by any
                // of the signers to protect APK contents.

                mV1SignerConfigs.Add(v1SignerConfig);
            }

            mV1ContentDigestAlgorithm = digestAlgorithm;
            mSignatureExpectedOutputJarEntryNames =
                V1SchemeSigner.getOutputEntryNames(mV1SignerConfigs);
        }

        private List<ApkSigningBlockUtils.SignerConfig> createV2SignerConfigs(
            bool apkSigningBlockPaddingSupported)

        {
            if (mV3SigningEnabled)
            {
                // v3 signing only supports single signers, of which the oldest (first) will be the one
                // to use for v1 and v2 signing
                List<ApkSigningBlockUtils.SignerConfig> signerConfig = new List<ApkSigningBlockUtils.SignerConfig>();

                SignerConfig oldestConfig = mSignerConfigs[0];

                // first make sure that if we have signing certificate history that the oldest signer
                // corresponds to the oldest ancestor
                if (mSigningCertificateLineage != null)
                {
                    SigningCertificateLineage subLineage =
                        mSigningCertificateLineage.getSubLineage(oldestConfig.mCertificates[0]);
                    if (subLineage.size() != 1)
                    {
                        throw new ArgumentException(
                            "v2 signing enabled but the oldest signer in"
                            + " the SigningCertificateLineage is missing.  Please provide"
                            + " the oldest signer to enable v2 signing.");
                    }
                }

                signerConfig.Add(
                    createSigningBlockSignerConfig(
                        mSignerConfigs[0],
                        apkSigningBlockPaddingSupported,
                        ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2));
                return signerConfig;
            }
            else
            {
                return createSigningBlockSignerConfigs(
                    apkSigningBlockPaddingSupported,
                    ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2);
            }
        }

        private List<ApkSigningBlockUtils.SignerConfig> processV3Configs(
            List<ApkSigningBlockUtils.SignerConfig> rawConfigs)

        {
            List<ApkSigningBlockUtils.SignerConfig> processedConfigs = new List<ApkSigningBlockUtils.SignerConfig>();

            // we have our configs, now touch them up to appropriately cover all SDK levels since APK
            // signature scheme v3 was introduced
            int currentMinSdk = int.MaxValue;
            for (int i = rawConfigs.Count - 1; i >= 0; i--)
            {
                ApkSigningBlockUtils.SignerConfig config = rawConfigs[i];
                if (config.signatureAlgorithms == null)
                {
                    // no valid algorithm was found for this signer, and we haven't yet covered all
                    // platform versions, something's wrong
                    String keyAlgorithm = config.certificates[0].getPublicKey().getAlgorithm();
                    throw new CryptographicException(
                        "Unsupported key algorithm "
                        + keyAlgorithm
                        + " is "
                        + "not supported for APK Signature Scheme v3 signing");
                }

                if (i == rawConfigs.Count - 1)
                {
                    // first go through the loop, config should support all future platform versions.
                    // this assumes we don't deprecate support for signers in the future.  If we do,
                    // this needs to change
                    config.maxSdkVersion = int.MaxValue;
                }
                else
                {
                    // otherwise, we only want to use this signer up to the minimum platform version
                    // on which a newer one is acceptable
                    config.maxSdkVersion = currentMinSdk - 1;
                }

                config.minSdkVersion = getMinSdkFromV3SignatureAlgorithms(config.signatureAlgorithms);
                if (mSigningCertificateLineage != null)
                {
                    config.mSigningCertificateLineage =
                        mSigningCertificateLineage.getSubLineage(config.certificates[0]);
                }

                // we know that this config will be used, so add it to our result, order doesn't matter
                // at this point (and likely only one will be needed
                processedConfigs.Add(config);
                currentMinSdk = config.minSdkVersion;
                if (currentMinSdk <= mMinSdkVersion || currentMinSdk <= AndroidSdkVersion.P)
                {
                    // this satisfies all we need, stop here
                    break;
                }
            }

            if (currentMinSdk > AndroidSdkVersion.P && currentMinSdk > mMinSdkVersion)
            {
                // we can't cover all desired SDK versions, abort
                throw new CryptographicException(
                    "Provided key algorithms not supported on all desired "
                    + "Android SDK versions");
            }

            return processedConfigs;
        }

        private List<ApkSigningBlockUtils.SignerConfig> createV3SignerConfigs(
            bool apkSigningBlockPaddingSupported)

        {
            return processV3Configs(createSigningBlockSignerConfigs(apkSigningBlockPaddingSupported,
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3));
        }

        private ApkSigningBlockUtils.SignerConfig createV4SignerConfig()
        {
            List<ApkSigningBlockUtils.SignerConfig> configs = createSigningBlockSignerConfigs(true,
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V4);
            if (configs.Count != 1)
            {
                // V4 only uses signer config to connect back to v3. Use the same filtering logic.
                configs = processV3Configs(configs);
            }

            if (configs.Count != 1)
            {
                throw new CryptographicException("Only accepting one signer config for V4 Signature.");
            }

            return configs[0];
        }

        private ApkSigningBlockUtils.SignerConfig createSourceStampSignerConfig()
        {
            ApkSigningBlockUtils.SignerConfig config = createSigningBlockSignerConfig(
                mSourceStampSignerConfig,
                /* apkSigningBlockPaddingSupported= */ false,
                ApkSigningBlockUtils.VERSION_SOURCE_STAMP);
            if (mSourceStampSigningCertificateLineage != null)
            {
                config.mSigningCertificateLineage = mSourceStampSigningCertificateLineage.getSubLineage(
                    config.certificates[0]);
            }

            return config;
        }

        private int getMinSdkFromV3SignatureAlgorithms(List<SignatureAlgorithm> algorithms)
        {
            int min = int.MaxValue;
            foreach (SignatureAlgorithm algorithm in algorithms)
            {
                int current = algorithm.getMinSdkVersion();
                if (current < min)
                {
                    if (current <= mMinSdkVersion || current <= AndroidSdkVersion.P)
                    {
                        // this algorithm satisfies all of our needs, no need to keep looking
                        return current;
                    }
                    else
                    {
                        min = current;
                    }
                }
            }

            return min;
        }

        private List<ApkSigningBlockUtils.SignerConfig> createSigningBlockSignerConfigs(
            bool apkSigningBlockPaddingSupported, int schemeId)

        {
            List<ApkSigningBlockUtils.SignerConfig> signerConfigs =
                new List<ApkSigningBlockUtils.SignerConfig>(mSignerConfigs.Count);
            for (int i = 0; i < mSignerConfigs.Count; i++)
            {
                SignerConfig signerConfig = mSignerConfigs[i];
                signerConfigs.Add(
                    createSigningBlockSignerConfig(
                        signerConfig, apkSigningBlockPaddingSupported, schemeId));
            }

            return signerConfigs;
        }

        private ApkSigningBlockUtils.SignerConfig createSigningBlockSignerConfig(
            SignerConfig signerConfig, bool apkSigningBlockPaddingSupported, int schemeId)

        {
            List<X509Certificate> certificates = signerConfig.getCertificates();
            PublicKey publicKey = certificates[0].getPublicKey();

            ApkSigningBlockUtils.SignerConfig newSignerConfig = new ApkSigningBlockUtils.SignerConfig();
            newSignerConfig.privateKey = signerConfig.getPrivateKey();
            newSignerConfig.certificates = certificates;

            switch (schemeId)
            {
                case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2:
                    newSignerConfig.signatureAlgorithms =
                        V2SchemeSigner.getSuggestedSignatureAlgorithms(
                            publicKey,
                            mMinSdkVersion,
                            apkSigningBlockPaddingSupported && mVerityEnabled,
                            signerConfig.getDeterministicDsaSigning());
                    break;
                case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3:
                    try
                    {
                        newSignerConfig.signatureAlgorithms =
                            V3SchemeSigner.getSuggestedSignatureAlgorithms(
                                publicKey,
                                mMinSdkVersion,
                                apkSigningBlockPaddingSupported && mVerityEnabled,
                                signerConfig.getDeterministicDsaSigning());
                    }
                    catch (CryptographicException e)
                    {
                        // It is possible for a signer used for v1/v2 signing to not be allowed for use
                        // with v3 signing.  This is ok as long as there exists a more recent v3 signer
                        // that covers all supported platform versions.  Populate signatureAlgorithm
                        // with null, it will be cleaned-up in a later step.
                        newSignerConfig.signatureAlgorithms = null;
                    }

                    break;
                case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V4:
                    try
                    {
                        newSignerConfig.signatureAlgorithms =
                            V4SchemeSigner.getSuggestedSignatureAlgorithms(
                                publicKey, mMinSdkVersion, apkSigningBlockPaddingSupported,
                                signerConfig.getDeterministicDsaSigning());
                    }
                    catch (CryptographicException e)
                    {
                        // V4 is an optional signing schema, ok to proceed without.
                        newSignerConfig.signatureAlgorithms = null;
                    }

                    break;
                case ApkSigningBlockUtils.VERSION_SOURCE_STAMP:
                    newSignerConfig.signatureAlgorithms = new List<SignatureAlgorithm>
                    {
                        SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256
                    };
                    break;
                default:
                    throw new ArgumentException("Unknown APK Signature Scheme ID requested");
            }

            return newSignerConfig;
        }

        private bool isDebuggable(String entryName)
        {
            return mDebuggableApkPermitted
                   || !ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME.Equals(entryName);
        }

        /**
         * Initializes DefaultApkSignerEngine with the existing MANIFEST.MF. This reads existing digests
         * from the MANIFEST.MF file (they are assumed correct) and stores them for the readonly signature
         * without recalculation. This step has a significant performance benefit in case of incremental
         * build.
         *
         * <p>This method extracts and stored computed digest for every entry that it would compute it
         * for in the {@link #outputJarEntry(String)} method
         *
         * @param manifestBytes raw representation of MANIFEST.MF file
         * @param entryNames a set of expected entries names
         * @return set of entry names which were processed by the engine during the initialization, a
         *     subset of entryNames
         */
        public ISet<String> initWith(byte[] manifestBytes, ISet<String> entryNames)
        {
            V1SchemeVerifier.Result result = new V1SchemeVerifier.Result();
            Tuple<ManifestParser.Section, Dictionary<String, ManifestParser.Section>> sections =
                V1SchemeVerifier.parseManifest(manifestBytes, entryNames, result);
            String alg = V1SchemeSigner.getJcaMessageDigestAlgorithm(mV1ContentDigestAlgorithm);
            foreach (var entry in sections.Item2)
            {
                String entryName = entry.Key;
                if (V1SchemeSigner.isJarEntryDigestNeededInManifest(entry.Key)
                    && isDebuggable(entryName))
                {
                    V1SchemeVerifier.NamedDigest extractedDigest = null;
                    IList<V1SchemeVerifier.NamedDigest> digestsToVerify =
                        V1SchemeVerifier.getDigestsToVerify(
                            entry.Value, "-Digest", mMinSdkVersion, int.MaxValue);
                    foreach (V1SchemeVerifier.NamedDigest digestToVerify in digestsToVerify)
                    {
                        if (digestToVerify.jcaDigestAlgorithm.Equals(alg))
                        {
                            extractedDigest = digestToVerify;
                            break;
                        }
                    }

                    if (extractedDigest != null)
                    {
                        mOutputJarEntryDigests.Add(entryName, extractedDigest.digest);
                    }
                }
            }

            return new HashSet<string>(mOutputJarEntryDigests.Keys);
        }


        public void setExecutor(RunnablesExecutor executor)
        {
            mExecutor = executor;
        }


        public void inputApkSigningBlock(DataSource apkSigningBlock)
        {
            checkNotClosed();

            if ((apkSigningBlock == null) || (apkSigningBlock.size() == 0))
            {
                return;
            }

            if (mOtherSignersSignaturesPreserved)
            {
                bool schemeSignatureBlockPreserved = false;
                mPreservedSignatureBlocks = new List<Tuple<byte[], int>>();
                try
                {
                    List<Tuple<byte[], int>> signatureBlocks =
                        ApkSigningBlockUtils.getApkSignatureBlocks(apkSigningBlock);
                    foreach (Tuple<byte[], int> signatureBlock in signatureBlocks)
                    {
                        if (signatureBlock.Item2 == Constants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID)
                        {
                            // If a V2 signature block is found and the engine is configured to use V2
                            // then save any of the previous signers that are not part of the current
                            // signing request.
                            if (mV2SigningEnabled)
                            {
                                List<Tuple<List<X509Certificate>, byte[]>> v2Signers =
                                    ApkSigningBlockUtils.getApkSignatureBlockSigners(
                                        signatureBlock.Item1);
                                mPreservedV2Signers = new List<byte[]>(v2Signers.Count);
                                foreach (Tuple<List<X509Certificate>, byte[]> v2Signer in v2Signers)
                                {
                                    if (!isConfiguredWithSigner(v2Signer.Item1))
                                    {
                                        mPreservedV2Signers.Add(v2Signer.Item2);
                                        schemeSignatureBlockPreserved = true;
                                    }
                                }
                            }
                            else
                            {
                                // else V2 signing is not enabled; save the entire signature block to be
                                // added to the readonly APK signing block.
                                mPreservedSignatureBlocks.Add(signatureBlock);
                                schemeSignatureBlockPreserved = true;
                            }
                        }
                        else if (signatureBlock.Item2
                                 == Constants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID)
                        {
                            // Preserving other signers in the presence of a V3 signature block is only
                            // supported if the engine is configured to resign the APK with the V3
                            // signature scheme, and the V3 signer in the signature block is the same
                            // as the engine is configured to use.
                            if (!mV3SigningEnabled)
                            {
                                throw new InvalidOperationException(
                                    "Preserving an existing V3 signature is not supported");
                            }

                            List<Tuple<List<X509Certificate>, byte[]>> v3Signers =
                                ApkSigningBlockUtils.getApkSignatureBlockSigners(
                                    signatureBlock.Item1);
                            if (v3Signers.Count > 1)
                            {
                                throw new ArgumentException(
                                    "The provided APK signing block contains " + v3Signers.Count
                                                                               + " V3 signers; the V3 signature scheme only supports"
                                                                               + " one signer");
                            }

                            // If there is only a single V3 signer then ensure it is the signer
                            // configured to sign the APK.
                            if (v3Signers.Count == 1
                                && !isConfiguredWithSigner(v3Signers[0].Item1))
                            {
                                throw new InvalidOperationException(
                                    "The V3 signature scheme only supports one signer; a request "
                                    + "was made to preserve the existing V3 signature, "
                                    + "but the engine is configured to sign with a "
                                    + "different signer");
                            }
                        }
                        else if (!DISCARDED_SIGNATURE_BLOCK_IDS.Contains(
                                     signatureBlock.Item2))
                        {
                            mPreservedSignatureBlocks.Add(signatureBlock);
                        }
                    }
                }
                catch (Exception e) when (e is ApkFormatException || e is CryptographicException ||
                                          e is System.IO.IOException)
                {
                    throw new ArgumentException("Unable to parse the provided signing block", e);
                }

                // Signature scheme V3+ only support a single signer; if the engine is configured to
                // sign with V3+ then ensure no scheme signature blocks have been preserved.
                if (mV3SigningEnabled && schemeSignatureBlockPreserved)
                {
                    throw new InvalidOperationException(
                        "Signature scheme V3+ only supports a single signer and cannot be "
                        + "appended to the existing signature scheme blocks");
                }

                return;
            }
        }

        /**
     * Returns whether the engine is configured to sign the APK with a signer using the specified
     * {@code signerCerts}.
     */
        private bool isConfiguredWithSigner(List<X509Certificate> signerCerts)
        {
            foreach (SignerConfig signerConfig in mSignerConfigs)
            {
                if (signerConfig.getCertificates().All(c => signerCerts.Contains(c)))
                {
                    return true;
                }
            }

            return false;
        }


        public InputJarEntryInstructions inputJarEntry(String entryName)
        {
            checkNotClosed();

            InputJarEntryInstructions.OutputPolicy outputPolicy =
                getInputJarEntryOutputPolicy(entryName);
            switch (outputPolicy)
            {
                case InputJarEntryInstructions.OutputPolicy.SKIP:
                    return new InputJarEntryInstructions(InputJarEntryInstructions.OutputPolicy.SKIP);
                case InputJarEntryInstructions.OutputPolicy.OUTPUT:
                    return new InputJarEntryInstructions(InputJarEntryInstructions.OutputPolicy.OUTPUT);
                case InputJarEntryInstructions.OutputPolicy.OUTPUT_BY_ENGINE:
                    if (V1SchemeConstants.MANIFEST_ENTRY_NAME.Equals(entryName))
                    {
                        // We copy the main section of the JAR manifest from input to output. Thus, this
                        // invalidates v1 signature and we need to see the entry's data.
                        mInputJarManifestEntryDataRequest = new GetJarEntryDataRequest(entryName);
                        return new InputJarEntryInstructions(
                            InputJarEntryInstructions.OutputPolicy.OUTPUT_BY_ENGINE,
                            mInputJarManifestEntryDataRequest);
                    }

                    return new InputJarEntryInstructions(
                        InputJarEntryInstructions.OutputPolicy.OUTPUT_BY_ENGINE);
                default:
                    throw new ApplicationException("Unsupported output policy: " + outputPolicy);
            }
        }


        public InspectJarEntryRequest outputJarEntry(String entryName)
        {
            checkNotClosed();
            invalidateV2Signature();

            if (!isDebuggable(entryName))
            {
                forgetOutputApkDebuggableStatus();
            }

            if (!mV1SigningEnabled)
            {
                // No need to inspect JAR entries when v1 signing is not enabled.
                if (!isDebuggable(entryName))
                {
                    // To reject debuggable APKs we need to inspect the APK's AndroidManifest.xml to
                    // check whether it declares that the APK is debuggable
                    mOutputAndroidManifestEntryDataRequest = new GetJarEntryDataRequest(entryName);
                    return mOutputAndroidManifestEntryDataRequest;
                }

                return null;
            }
            // v1 signing is enabled

            if (V1SchemeSigner.isJarEntryDigestNeededInManifest(entryName))
            {
                // This entry is covered by v1 signature. We thus need to inspect the entry's data to
                // compute its digest(s) for v1 signature.

                // TODO: Handle the case where other signer's v1 signatures are present and need to be
                // preserved. In that scenario we can't modify MANIFEST.MF and add/remove JAR entries
                // covered by v1 signature.
                invalidateV1Signature();
                GetJarEntryDataDigestRequest dataDigestRequest =
                    new GetJarEntryDataDigestRequest(
                        entryName,
                        V1SchemeSigner.getJcaMessageDigestAlgorithm(mV1ContentDigestAlgorithm));
                mOutputJarEntryDigestRequests.Add(entryName, dataDigestRequest);
                mOutputJarEntryDigests.Remove(entryName);

                if ((!mDebuggableApkPermitted)
                    && (ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME.Equals(entryName)))
                {
                    // To reject debuggable APKs we need to inspect the APK's AndroidManifest.xml to
                    // check whether it declares that the APK is debuggable
                    mOutputAndroidManifestEntryDataRequest = new GetJarEntryDataRequest(entryName);
                    return new CompoundInspectJarEntryRequest(
                        entryName, mOutputAndroidManifestEntryDataRequest, dataDigestRequest);
                }

                return dataDigestRequest;
            }

            if (mSignatureExpectedOutputJarEntryNames.Contains(entryName))
            {
                // This entry is part of v1 signature generated by this engine. We need to check whether
                // the entry's data is as output by the engine.
                invalidateV1Signature();
                GetJarEntryDataRequest dataRequest;
                if (V1SchemeConstants.MANIFEST_ENTRY_NAME.Equals(entryName))
                {
                    dataRequest = new GetJarEntryDataRequest(entryName);
                    mInputJarManifestEntryDataRequest = dataRequest;
                }
                else
                {
                    // If this entry is part of v1 signature which has been emitted by this engine,
                    // check whether the output entry's data matches what the engine emitted.
                    dataRequest =
                        (mEmittedSignatureJarEntryData.ContainsKey(entryName))
                            ? new GetJarEntryDataRequest(entryName)
                            : null;
                }

                if (dataRequest != null)
                {
                    mOutputSignatureJarEntryDataRequests.Add(entryName, dataRequest);
                }

                return dataRequest;
            }

            // This entry is not covered by v1 signature and isn't part of v1 signature.
            return null;
        }


        public InputJarEntryInstructions.OutputPolicy inputJarEntryRemoved(String entryName)
        {
            checkNotClosed();
            return getInputJarEntryOutputPolicy(entryName);
        }


        public void outputJarEntryRemoved(String entryName)
        {
            checkNotClosed();
            invalidateV2Signature();
            if (!mV1SigningEnabled)
            {
                return;
            }

            if (V1SchemeSigner.isJarEntryDigestNeededInManifest(entryName))
            {
                // This entry is covered by v1 signature.
                invalidateV1Signature();
                mOutputJarEntryDigests.Remove(entryName);
                mOutputJarEntryDigestRequests.Remove(entryName);
                mOutputSignatureJarEntryDataRequests.Remove(entryName);
                return;
            }

            if (mSignatureExpectedOutputJarEntryNames.Contains(entryName))
            {
                // This entry is part of the v1 signature generated by this engine.
                invalidateV1Signature();
                return;
            }
        }


        public OutputJarSignatureRequest outputJarEntries()
        {
            checkNotClosed();

            if (!mV1SignaturePending)
            {
                return null;
            }

            if ((mInputJarManifestEntryDataRequest != null)
                && (!mInputJarManifestEntryDataRequest.isDone()))
            {
                throw new InvalidOperationException(
                    "Still waiting to inspect input APK's "
                    + mInputJarManifestEntryDataRequest.getEntryName());
            }

            foreach (GetJarEntryDataDigestRequest digestRequest in mOutputJarEntryDigestRequests.Values)
            {
                String entryName = digestRequest.getEntryName();
                if (!digestRequest.isDone())
                {
                    throw new InvalidOperationException(
                        "Still waiting to inspect output APK's " + entryName);
                }

                mOutputJarEntryDigests.Add(entryName, digestRequest.getDigest());
            }

            if (isEligibleForSourceStamp())
            {
                HashAlgorithm messageDigest =
                    HashAlgorithm.Create(V1SchemeSigner.getJcaMessageDigestAlgorithm(mV1ContentDigestAlgorithm));
                mOutputJarEntryDigests.Add(
                    ApkUtils.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME,
                    messageDigest.ComputeHash(generateSourceStampCertificateDigest()));
            }

            mOutputJarEntryDigestRequests.Clear();

            foreach (GetJarEntryDataRequest dataRequest in mOutputSignatureJarEntryDataRequests.Values)
            {
                if (!dataRequest.isDone())
                {
                    throw new InvalidOperationException(
                        "Still waiting to inspect output APK's " + dataRequest.getEntryName());
                }
            }

            List<int> apkSigningSchemeIds = new List<int>();
            if (mV2SigningEnabled)
            {
                apkSigningSchemeIds.Add(ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2);
            }

            if (mV3SigningEnabled)
            {
                apkSigningSchemeIds.Add(ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
            }

            byte[] inputJarManifest =
                (mInputJarManifestEntryDataRequest != null)
                    ? mInputJarManifestEntryDataRequest.getData()
                    : null;
            if (isEligibleForSourceStamp())
            {
                inputJarManifest =
                    V1SchemeSigner.generateManifestFile(
                            mV1ContentDigestAlgorithm,
                            mOutputJarEntryDigests,
                            inputJarManifest)
                        .contents;
            }

            // Check whether the most recently used signature (if present) is still fine.
            checkOutputApkNotDebuggableIfDebuggableMustBeRejected();
            List<Tuple<String, byte[]>> signatureZipEntries;
            if ((mAddV1SignatureRequest == null) || (!mAddV1SignatureRequest.isDone()))
            {
                try
                {
                    signatureZipEntries =
                        V1SchemeSigner.sign(
                            mV1SignerConfigs,
                            mV1ContentDigestAlgorithm,
                            mOutputJarEntryDigests,
                            apkSigningSchemeIds,
                            inputJarManifest,
                            mCreatedBy);
                }
                catch (CryptographicException e)
                {
                    throw new CryptographicException("Failed to generate v1 signature", e);
                }
            }
            else
            {
                V1SchemeSigner.OutputManifestFile newManifest =
                    V1SchemeSigner.generateManifestFile(
                        mV1ContentDigestAlgorithm, mOutputJarEntryDigests, inputJarManifest);
                byte[] emittedSignatureManifest =
                    mEmittedSignatureJarEntryData[V1SchemeConstants.MANIFEST_ENTRY_NAME];
                if (!newManifest.contents.SequenceEqual(emittedSignatureManifest))
                {
                    // Emitted v1 signature is no longer valid.
                    try
                    {
                        signatureZipEntries =
                            V1SchemeSigner.signManifest(
                                mV1SignerConfigs,
                                mV1ContentDigestAlgorithm,
                                apkSigningSchemeIds,
                                mCreatedBy,
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
                    foreach (var expectedOutputEntry in mEmittedSignatureJarEntryData)
                    {
                        String entryName = expectedOutputEntry.Key;
                        byte[] expectedData = expectedOutputEntry.Value;
                        mOutputSignatureJarEntryDataRequests.TryGetValue(entryName, out var actualDataRequest);
                        if (actualDataRequest == null)
                        {
                            // This signature entry hasn't been output.
                            signatureZipEntries.Add(Tuple.Create(entryName, expectedData));
                            continue;
                        }

                        byte[] actualData = actualDataRequest.getData();
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
                mV1SignaturePending = false;
                return null;
            }

            List<OutputJarSignatureRequestJarEntry> sigEntries =
                new List<OutputJarSignatureRequestJarEntry>(signatureZipEntries.Count);
            foreach (Tuple<String, byte[]> entry in signatureZipEntries)
            {
                String entryName = entry.Item1;
                byte[] entryData = entry.Item2;
                sigEntries.Add(new OutputJarSignatureRequestJarEntry(entryName, entryData));
                mEmittedSignatureJarEntryData.Add(entryName, entryData);
            }

            mAddV1SignatureRequest = new OutputJarSignatureRequestImpl(sigEntries);
            return mAddV1SignatureRequest;
        }

        [Obsolete]
        public OutputApkSigningBlockRequest outputZipSections(
            DataSource zipEntries, DataSource zipCentralDirectory, DataSource zipEocd)

        {
            return outputZipSectionsInternal(zipEntries, zipCentralDirectory, zipEocd, false);
        }


        public OutputApkSigningBlockRequest2 outputZipSections2(
            DataSource zipEntries, DataSource zipCentralDirectory, DataSource zipEocd)

        {
            return outputZipSectionsInternal(zipEntries, zipCentralDirectory, zipEocd, true);
        }

        private OutputApkSigningBlockRequestImpl outputZipSectionsInternal(
            DataSource zipEntries,
            DataSource zipCentralDirectory,
            DataSource zipEocd,
            bool apkSigningBlockPaddingSupported)

        {
            checkNotClosed();
            checkV1SigningDoneIfEnabled();
            if (!mV2SigningEnabled && !mV3SigningEnabled && !isEligibleForSourceStamp())
            {
                return null;
            }

            checkOutputApkNotDebuggableIfDebuggableMustBeRejected();

            // adjust to proper padding
            Tuple<DataSource, int> paddingPair =
                ApkSigningBlockUtils.generateApkSigningBlockPadding(
                    zipEntries, apkSigningBlockPaddingSupported);
            DataSource beforeCentralDir = paddingPair.Item1;
            int padSizeBeforeApkSigningBlock = paddingPair.Item2;
            DataSource eocd = ApkSigningBlockUtils.copyWithModifiedCDOffset(beforeCentralDir, zipEocd);

            List<Tuple<byte[], int>> signingSchemeBlocks = new List<Tuple<byte[], int>>();
            ApkSigningBlockUtils.SigningSchemeBlockAndDigests v2SigningSchemeBlockAndDigests = null;
            ApkSigningBlockUtils.SigningSchemeBlockAndDigests v3SigningSchemeBlockAndDigests = null;
            // If the engine is configured to preserve previous signature blocks and any were found in
            // the existing APK signing block then add them to the list to be used to generate the
            // new APK signing block.
            if (mOtherSignersSignaturesPreserved && mPreservedSignatureBlocks != null
                                                 && mPreservedSignatureBlocks.Count != 0)
            {
                signingSchemeBlocks.AddRange(mPreservedSignatureBlocks);
            }

            // create APK Signature Scheme V2 Signature if requested
            if (mV2SigningEnabled)
            {
                invalidateV2Signature();
                List<ApkSigningBlockUtils.SignerConfig> v2SignerConfigs =
                    createV2SignerConfigs(apkSigningBlockPaddingSupported);
                v2SigningSchemeBlockAndDigests =
                    V2SchemeSigner.generateApkSignatureSchemeV2Block(
                        mExecutor,
                        beforeCentralDir,
                        zipCentralDirectory,
                        eocd,
                        v2SignerConfigs,
                        mV3SigningEnabled,
                        mOtherSignersSignaturesPreserved ? mPreservedV2Signers : null);
                signingSchemeBlocks.Add(v2SigningSchemeBlockAndDigests.signingSchemeBlock);
            }

            if (mV3SigningEnabled)
            {
                invalidateV3Signature();
                List<ApkSigningBlockUtils.SignerConfig> v3SignerConfigs =
                    createV3SignerConfigs(apkSigningBlockPaddingSupported);
                v3SigningSchemeBlockAndDigests =
                    V3SchemeSigner.generateApkSignatureSchemeV3Block(
                        mExecutor,
                        beforeCentralDir,
                        zipCentralDirectory,
                        eocd,
                        v3SignerConfigs);
                signingSchemeBlocks.Add(v3SigningSchemeBlockAndDigests.signingSchemeBlock);
            }

            if (isEligibleForSourceStamp())
            {
                ApkSigningBlockUtils.SignerConfig sourceStampSignerConfig =
                    createSourceStampSignerConfig();
                Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> signatureSchemeDigestInfos =
                    new Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>>();
                if (mV3SigningEnabled)
                {
                    signatureSchemeDigestInfos.Add(
                        ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3,
                        v3SigningSchemeBlockAndDigests.digestInfo);
                }

                if (mV2SigningEnabled)
                {
                    signatureSchemeDigestInfos.Add(
                        ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2,
                        v2SigningSchemeBlockAndDigests.digestInfo);
                }

                if (mV1SigningEnabled)
                {
                    Dictionary<ContentDigestAlgorithm, byte[]> v1SigningSchemeDigests =
                        new Dictionary<ContentDigestAlgorithm, byte[]>();
                    try
                    {
                        // Jar signing related variables must have been already populated at this point
                        // if V1 signing is enabled since it is happening before computations on the APK
                        // signing block (V2/V3/V4/SourceStamp signing).
                        byte[] inputJarManifest =
                            (mInputJarManifestEntryDataRequest != null)
                                ? mInputJarManifestEntryDataRequest.getData()
                                : null;
                        byte[] jarManifest =
                            V1SchemeSigner.generateManifestFile(
                                    mV1ContentDigestAlgorithm,
                                    mOutputJarEntryDigests,
                                    inputJarManifest)
                                .contents;
                        // The digest of the jar manifest does not need to be computed in chunks due to
                        // the small size of the manifest.
                        v1SigningSchemeDigests.Add(
                            ContentDigestAlgorithm.SHA256, ApkUtils.computeSha256DigestBytes(jarManifest));
                    }
                    catch (ApkFormatException e)
                    {
                        throw new ApplicationException("Failed to generate manifest file", e);
                    }

                    signatureSchemeDigestInfos.Add(
                        ApkSigningBlockUtils.VERSION_JAR_SIGNATURE_SCHEME, v1SigningSchemeDigests);
                }

                signingSchemeBlocks.Add(
                    V2SourceStampSigner.generateSourceStampBlock(
                        sourceStampSignerConfig, signatureSchemeDigestInfos));
            }

            // create APK Signing Block with v2 and/or v3 and/or SourceStamp blocks
            byte[] apkSigningBlock = ApkSigningBlockUtils.generateApkSigningBlock(signingSchemeBlocks);

            mAddSigningBlockRequest =
                new OutputApkSigningBlockRequestImpl(apkSigningBlock, padSizeBeforeApkSigningBlock);
            return mAddSigningBlockRequest;
        }


        public void outputDone()
        {
            checkNotClosed();
            checkV1SigningDoneIfEnabled();
            checkSigningBlockDoneIfEnabled();
        }


        public void signV4(DataSource dataSource, FileInfo outputFile, bool ignoreFailures)
        {
            if (outputFile == null)
            {
                if (ignoreFailures)
                {
                    return;
                }

                throw new CryptographicException("Missing V4 output file.");
            }

            try
            {
                ApkSigningBlockUtils.SignerConfig v4SignerConfig = createV4SignerConfig();
                V4SchemeSigner.generateV4Signature(dataSource, v4SignerConfig, outputFile);
            }
            catch (Exception e) when (e is CryptographicException || e is IOException)
            {
                if (ignoreFailures)
                {
                    return;
                }

                throw new CryptographicException("V4 signing failed", e);
            }
        }

        /** For external use only to generate V4 & tree separately. */
        public byte[] produceV4Signature(DataSource dataSource, Stream sigOutput)
        {
            if (sigOutput == null)
            {
                throw new CryptographicException("Missing V4 output streams.");
            }

            try
            {
                ApkSigningBlockUtils.SignerConfig v4SignerConfig = createV4SignerConfig();
                Tuple<V4Signature, byte[]> pair =
                    V4SchemeSigner.generateV4Signature(dataSource, v4SignerConfig);
                pair.Item1.writeTo(sigOutput);
                return pair.Item2;
            }
            catch (Exception e) when (e is CryptographicException || e is IOException)
            {
                throw new CryptographicException("V4 signing failed", e);
            }
        }


        public bool isEligibleForSourceStamp()
        {
            return mSourceStampSignerConfig != null
                   && (mV2SigningEnabled || mV3SigningEnabled || mV1SigningEnabled);
        }


        public byte[] generateSourceStampCertificateDigest()
        {
            if (mSourceStampSignerConfig.getCertificates().Count == 0)
            {
                throw new CryptographicException("No certificates configured for stamp");
            }

            try
            {
                return ApkUtils.computeSha256DigestBytes(
                    mSourceStampSignerConfig.getCertificates()[0].getEncoded());
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException("Failed to encode source stamp certificate", e);
            }
        }


        public void Dispose()
        {
            mClosed = true;

            mAddV1SignatureRequest = null;
            mInputJarManifestEntryDataRequest = null;
            mOutputAndroidManifestEntryDataRequest = null;
            mDebuggable = null;
            mOutputJarEntryDigestRequests.Clear();
            mOutputJarEntryDigests.Clear();
            mEmittedSignatureJarEntryData.Clear();
            mOutputSignatureJarEntryDataRequests.Clear();

            mAddSigningBlockRequest = null;
        }

        private void invalidateV1Signature()
        {
            if (mV1SigningEnabled)
            {
                mV1SignaturePending = true;
            }

            invalidateV2Signature();
        }

        private void invalidateV2Signature()
        {
            if (mV2SigningEnabled)
            {
                mV2SignaturePending = true;
                mAddSigningBlockRequest = null;
            }
        }

        private void invalidateV3Signature()
        {
            if (mV3SigningEnabled)
            {
                mV3SignaturePending = true;
                mAddSigningBlockRequest = null;
            }
        }

        private void checkNotClosed()
        {
            if (mClosed)
            {
                throw new InvalidOperationException("Engine closed");
            }
        }

        private void checkV1SigningDoneIfEnabled()
        {
            if (!mV1SignaturePending)
            {
                return;
            }

            if (mAddV1SignatureRequest == null)
            {
                throw new InvalidOperationException(
                    "v1 signature (JAR signature) not yet generated. Skipped outputJarEntries()?");
            }

            if (!mAddV1SignatureRequest.isDone())
            {
                throw new InvalidOperationException(
                    "v1 signature (JAR signature) addition requested by outputJarEntries() hasn't"
                    + " been fulfilled");
            }

            foreach (var expectedOutputEntry in mEmittedSignatureJarEntryData)
            {
                String entryName = expectedOutputEntry.Key;
                byte[] expectedData = expectedOutputEntry.Value;
                mOutputSignatureJarEntryDataRequests.TryGetValue(entryName, out var actualDataRequest);
                if (actualDataRequest == null)
                {
                    throw new InvalidOperationException(
                        "APK entry "
                        + entryName
                        + " not yet output despite this having been"
                        + " requested");
                }
                else if (!actualDataRequest.isDone())
                {
                    throw new InvalidOperationException(
                        "Still waiting to inspect output APK's " + entryName);
                }

                byte[] actualData = actualDataRequest.getData();
                if (!expectedData.SequenceEqual(actualData))
                {
                    throw new InvalidOperationException(
                        "Output APK entry " + entryName + " data differs from what was requested");
                }
            }

            mV1SignaturePending = false;
        }

        private void checkSigningBlockDoneIfEnabled()
        {
            if (!mV2SignaturePending && !mV3SignaturePending)
            {
                return;
            }

            if (mAddSigningBlockRequest == null)
            {
                throw new InvalidOperationException(
                    "Signed APK Signing BLock not yet generated. Skipped outputZipSections()?");
            }

            if (!mAddSigningBlockRequest.isDone())
            {
                throw new InvalidOperationException(
                    "APK Signing Block addition of signature(s) requested by"
                    + " outputZipSections() hasn't been fulfilled yet");
            }

            mAddSigningBlockRequest = null;
            mV2SignaturePending = false;
            mV3SignaturePending = false;
        }

        private void checkOutputApkNotDebuggableIfDebuggableMustBeRejected()
        {
            if (mDebuggableApkPermitted)
            {
                return;
            }

            try
            {
                if (isOutputApkDebuggable())
                {
                    throw new CryptographicException(
                        "APK is debuggable (see android:debuggable attribute) and this engine is"
                        + " configured to refuse to sign debuggable APKs");
                }
            }
            catch (ApkFormatException e)
            {
                throw new CryptographicException("Failed to determine whether the APK is debuggable", e);
            }
        }

        /**
     * Returns whether the output APK is debuggable according to its {@code android:debuggable}
     * declaration.
     */
        private bool isOutputApkDebuggable()
        {
            if (mDebuggable != null)
            {
                return mDebuggable.Value;
            }

            if (mOutputAndroidManifestEntryDataRequest == null)
            {
                throw new InvalidOperationException(
                    "Cannot determine debuggable status of output APK because "
                    + ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME
                    + " entry contents have not yet been requested");
            }

            if (!mOutputAndroidManifestEntryDataRequest.isDone())
            {
                throw new InvalidOperationException(
                    "Still waiting to inspect output APK's "
                    + mOutputAndroidManifestEntryDataRequest.getEntryName());
            }

            mDebuggable =
                ApkUtils.getDebuggableFromBinaryAndroidManifest(
                    ByteBuffer.wrap(mOutputAndroidManifestEntryDataRequest.getData()));
            return mDebuggable.Value;
        }

        private void forgetOutputApkDebuggableStatus()
        {
            mDebuggable = null;
        }

        /** Returns the output policy for the provided input JAR entry. */
        private InputJarEntryInstructions.OutputPolicy getInputJarEntryOutputPolicy(String entryName)
        {
            if (mSignatureExpectedOutputJarEntryNames.Contains(entryName))
            {
                return InputJarEntryInstructions.OutputPolicy.OUTPUT_BY_ENGINE;
            }

            if ((mOtherSignersSignaturesPreserved)
                || (V1SchemeSigner.isJarEntryDigestNeededInManifest(entryName)))
            {
                return InputJarEntryInstructions.OutputPolicy.OUTPUT;
            }

            return InputJarEntryInstructions.OutputPolicy.SKIP;
        }

        private class OutputJarSignatureRequestImpl : OutputJarSignatureRequest
        {
            private readonly List<OutputJarSignatureRequestJarEntry> mAdditionalJarEntries;

            private volatile bool
                mDone;

            public OutputJarSignatureRequestImpl(List<OutputJarSignatureRequestJarEntry> additionalZipEntries)
            {
                mAdditionalJarEntries = additionalZipEntries;
            }

            public List<OutputJarSignatureRequestJarEntry> getAdditionalJarEntries()
            {
                return mAdditionalJarEntries;
            }

            public void done()
            {
                mDone = true;
            }

            public bool isDone()
            {
                return mDone;
            }
        }

#pragma warning disable CS0612
        private class OutputApkSigningBlockRequestImpl : OutputApkSigningBlockRequest, OutputApkSigningBlockRequest2
#pragma warning restore CS0612
        {
            private readonly byte[] mApkSigningBlock;
            private readonly int mPaddingBeforeApkSigningBlock;
            private volatile bool mDone;

            public OutputApkSigningBlockRequestImpl(byte[] apkSigingBlock, int paddingBefore)
            {
                mApkSigningBlock = (byte[])apkSigingBlock.Clone();
                mPaddingBeforeApkSigningBlock = paddingBefore;
            }

            public byte[] getApkSigningBlock()
            {
                return (byte[])mApkSigningBlock.Clone();
            }

            public void done()
            {
                mDone = true;
            }

            public bool isDone()
            {
                return mDone;
            }

            public int getPaddingSizeBeforeApkSigningBlock()
            {
                return mPaddingBeforeApkSigningBlock;
            }
        }

        /** JAR entry inspection request which obtain the entry's uncompressed data. */
        private class GetJarEntryDataRequest : InspectJarEntryRequest
        {
            private readonly String mEntryName;
            private readonly Object mLock = new Object();
            private bool mDone;
            private DataSink mDataSink;
            private MemoryStream mDataSinkBuf;

            public GetJarEntryDataRequest(String entryName)
            {
                mEntryName = entryName;
            }


            public String getEntryName()
            {
                return mEntryName;
            }


            public DataSink getDataSink()
            {
                lock (mLock)
                {
                    checkNotDone();
                    if (mDataSinkBuf == null)
                    {
                        mDataSinkBuf = new MemoryStream();
                    }

                    if (mDataSink == null)
                    {
                        mDataSink = DataSinks.asDataSink(mDataSinkBuf);
                    }

                    return mDataSink;
                }
            }


            public void done()
            {
                lock (mLock)
                {
                    if (mDone)
                    {
                        return;
                    }

                    mDone = true;
                }
            }

            public bool isDone()
            {
                lock (mLock)
                {
                    return mDone;
                }
            }

            private void checkNotDone()
            {
                lock (mLock)
                {
                    if (mDone)
                    {
                        throw new InvalidOperationException("Already done");
                    }
                }
            }

            public byte[] getData()
            {
                lock (mLock)
                {
                    if (!mDone)
                    {
                        throw new InvalidOperationException("Not yet done");
                    }

                    return (mDataSinkBuf != null) ? mDataSinkBuf.ToArray() : new byte[0];
                }
            }
        }

        /** JAR entry inspection request which obtains the digest of the entry's uncompressed data. */
        private class GetJarEntryDataDigestRequest : InspectJarEntryRequest
        {
            private readonly String mEntryName;

            private readonly
                String mJcaDigestAlgorithm;

            private readonly Object mLock = new Object();
            private bool mDone;
            private DataSink mDataSink;
            private HashAlgorithm mMessageDigest;
            private byte[] mDigest;

            public GetJarEntryDataDigestRequest(String entryName, String jcaDigestAlgorithm)
            {
                mEntryName = entryName;
                mJcaDigestAlgorithm = jcaDigestAlgorithm;
            }

            public String getEntryName()
            {
                return mEntryName;
            }

            public DataSink getDataSink()
            {
                lock (mLock)
                {
                    checkNotDone();
                    if (mDataSink == null)
                    {
                        mDataSink = DataSinks.asDataSink(getMessageDigest());
                    }

                    return mDataSink;
                }
            }

            private HashAlgorithm getMessageDigest()
            {
                lock (mLock)
                {
                    if (mMessageDigest == null)
                    {
                        mMessageDigest = HashAlgorithm.Create(mJcaDigestAlgorithm);
                    }

                    return mMessageDigest ?? throw new CryptographicException(
                        mJcaDigestAlgorithm + " MessageDigest not available");
                }
            }

            public void done()
            {
                lock (mLock)
                {
                    if (mDone)
                    {
                        return;
                    }

                    mDone = true;
                    mDigest = getMessageDigest().ComputeHash(Array.Empty<byte>(), 0, 0);
                    mMessageDigest = null;
                    mDataSink = null;
                }
            }

            public bool isDone()
            {
                lock (mLock)
                {
                    return mDone;
                }
            }

            private void checkNotDone()
            {
                lock (mLock)
                {
                    if (mDone)
                    {
                        throw new InvalidOperationException("Already done");
                    }
                }
            }

            public byte[] getDigest()
            {
                lock (mLock)
                {
                    if (!mDone)
                    {
                        throw new InvalidOperationException("Not yet done");
                    }

                    return (byte[])mDigest.Clone();
                }
            }
        }

        /** JAR entry inspection request which transparently satisfies multiple such requests. */
        private class CompoundInspectJarEntryRequest : InspectJarEntryRequest
        {
            private readonly String mEntryName;
            private readonly InspectJarEntryRequest[] mRequests;
            private readonly Object mLock = new Object();

            private DataSink mSink;

            public CompoundInspectJarEntryRequest(
                String entryName, params InspectJarEntryRequest[] requests)
            {
                mEntryName = entryName;
                mRequests = requests;
            }


            public String getEntryName()
            {
                return mEntryName;
            }


            public DataSink getDataSink()
            {
                lock (mLock)
                {
                    if (mSink == null)
                    {
                        DataSink[] sinks = new DataSink[mRequests.Length];
                        for (int i = 0; i < sinks.Length; i++)
                        {
                            sinks[i] = mRequests[i].getDataSink();
                        }

                        mSink = new TeeDataSink(sinks);
                    }

                    return mSink;
                }
            }


            public void done()
            {
                foreach (InspectJarEntryRequest request in mRequests)
                {
                    request.done();
                }
            }
        }


        /**
         * Configuration of a signer.
         *
         * <p>Use {@link Builder} to obtain configuration instances.
         */
        public class SignerConfig
        {
            public readonly String mName;
            public readonly PrivateKey mPrivateKey;
            public readonly List<X509Certificate> mCertificates;
            public readonly bool mDeterministicDsaSigning;

            private SignerConfig(
                String name, PrivateKey privateKey, List<X509Certificate> certificates,
                bool deterministicDsaSigning)
            {
                mName = name;
                mPrivateKey = privateKey;
                mCertificates = certificates;
                mDeterministicDsaSigning = deterministicDsaSigning;
            }

            /** Returns the name of this signer. */
            public String getName()
            {
                return mName;
            }

            /** Returns the signing key of this signer. */
            public PrivateKey getPrivateKey()
            {
                return mPrivateKey;
            }

            /**
             * Returns the certificate(s) of this signer. The first certificate's public key corresponds
             * to this signer's private key.
             */
            public List<X509Certificate> getCertificates()
            {
                return mCertificates;
            }

            /**
             * If this signer is a DSA signer, whether or not the signing is done deterministically.
             */
            public bool getDeterministicDsaSigning()
            {
                return mDeterministicDsaSigning;
            }

            /** Builder of {@link SignerConfig} instances. */
            public class Builder
            {
                private readonly String mName;
                private readonly PrivateKey mPrivateKey;
                private readonly List<X509Certificate> mCertificates;
                private readonly bool mDeterministicDsaSigning;

                /**
                 * Constructs a new {@code Builder}.
                 *
                 * @param name signer's name. The name is reflected in the name of files comprising the
                 *     JAR signature of the APK.
                 * @param privateKey signing key
                 * @param certificates list of one or more X.509 certificates. The subject public key of
                 *     the first certificate must correspond to the {@code privateKey}.
                 */
                public Builder(String name, PrivateKey privateKey, List<X509Certificate> certificates)
                    : this(name, privateKey, certificates, false)
                {
                }

                /**
                 * Constructs a new {@code Builder}.
                 *
                 * @param name signer's name. The name is reflected in the name of files comprising the
                 *     JAR signature of the APK.
                 * @param privateKey signing key
                 * @param certificates list of one or more X.509 certificates. The subject public key of
                 *     the first certificate must correspond to the {@code privateKey}.
                 * @param deterministicDsaSigning When signing using DSA, whether or not the
                 * deterministic signing algorithm variant (RFC6979) should be used.
                 */
                public Builder(String name, PrivateKey privateKey, List<X509Certificate> certificates,
                    bool deterministicDsaSigning)
                {
                    if (name.Length == 0)
                    {
                        throw new ArgumentException("Empty name");
                    }

                    mName = name;
                    mPrivateKey = privateKey;
                    mCertificates = certificates;
                    mDeterministicDsaSigning = deterministicDsaSigning;
                }

                /**
                 * Returns a new {@code SignerConfig} instance configured based on the configuration of
                 * this builder.
                 */
                public SignerConfig build()
                {
                    return new SignerConfig(mName, mPrivateKey, mCertificates,
                        mDeterministicDsaSigning);
                }
            }
        }

        /** Builder of {@link DefaultApkSignerEngine} instances. */
        public class Builder
        {
            private List<SignerConfig> mSignerConfigs;
            private SignerConfig mStampSignerConfig;
            private SigningCertificateLineage mSourceStampSigningCertificateLineage;
            private readonly int mMinSdkVersion;

            private bool mV1SigningEnabled = true;
            private bool mV2SigningEnabled = true;
            private bool mV3SigningEnabled = true;
            private bool mVerityEnabled = false;
            private bool mDebuggableApkPermitted = true;
            private bool mOtherSignersSignaturesPreserved;
            private String mCreatedBy = "1.0 (Android)";

            private SigningCertificateLineage mSigningCertificateLineage;

            // APK Signature Scheme v3 only supports a single signing certificate, so to move to v3
            // signing by default, but not require prior clients to update to explicitly disable v3
            // signing for multiple signers, we modify the mV3SigningEnabled depending on the provided
            // inputs (multiple signers and mSigningCertificateLineage in particular).  Maintain two
            // extra variables to record whether or not mV3SigningEnabled has been set directly by a
            // client and so should override the default behavior.
            private bool mV3SigningExplicitlyDisabled = false;
            private bool mV3SigningExplicitlyEnabled = false;
            private DigestAlgorithm mDigestAlgorithm = DigestAlgorithm.SHA256;

            /**
         * Constructs a new {@code Builder}.
         *
         * @param signerConfigs information about signers with which the APK will be signed. At
         *     least one signer configuration must be provided.
         * @param minSdkVersion API Level of the oldest Android platform on which the APK is
         *     supposed to be installed. See {@code minSdkVersion} attribute in the APK's {@code
         *     AndroidManifest.xml}. The higher the version, the stronger signing features will be
         *     enabled.
         */
            public Builder(List<SignerConfig> signerConfigs, int minSdkVersion)
            {
                if (signerConfigs.Count == 0)
                {
                    throw new ArgumentException("At least one signer config must be provided");
                }

                if (signerConfigs.Count > 1)
                {
                    // APK Signature Scheme v3 only supports single signer, unless a
                    // SigningCertificateLineage is provided, in which case this will be reset to true,
                    // since we don't yet have a v4 scheme about which to worry
                    mV3SigningEnabled = false;
                }

                mSignerConfigs = new List<SignerConfig>(signerConfigs);
                mMinSdkVersion = minSdkVersion;
            }

            /**
         * Returns a new {@code DefaultApkSignerEngine} instance configured based on the
         * configuration of this builder.
         */
            public DefaultApkSignerEngine build()
            {
                if (mV3SigningExplicitlyDisabled && mV3SigningExplicitlyEnabled)
                {
                    throw new InvalidOperationException(
                        "Builder configured to both enable and disable APK "
                        + "Signature Scheme v3 signing");
                }

                if (mV3SigningExplicitlyDisabled)
                {
                    mV3SigningEnabled = false;
                }
                else if (mV3SigningExplicitlyEnabled)
                {
                    mV3SigningEnabled = true;
                }

                // make sure our signers are appropriately setup
                if (mSigningCertificateLineage != null)
                {
                    try
                    {
                        mSignerConfigs = mSigningCertificateLineage.sortSignerConfigs(mSignerConfigs);
                        if (!mV3SigningEnabled && mSignerConfigs.Count > 1)
                        {
                            // this is a strange situation: we've provided a valid rotation history, but
                            // are only signing with v1/v2.  blow up, since we don't know for sure with
                            // which signer the user intended to sign
                            throw new InvalidOperationException(
                                "Provided multiple signers which are part of the"
                                + " SigningCertificateLineage, but not signing with APK"
                                + " Signature Scheme v3");
                        }
                    }
                    catch (ArgumentException e)
                    {
                        throw new InvalidOperationException(
                            "Provided signer configs do not match the "
                            + "provided SigningCertificateLineage",
                            e);
                    }
                }
                else if (mV3SigningEnabled && mSignerConfigs.Count > 1)
                {
                    throw new InvalidOperationException(
                        "Multiple signing certificates provided for use with APK Signature Scheme"
                        + " v3 without an accompanying SigningCertificateLineage");
                }

                return new DefaultApkSignerEngine(
                    mSignerConfigs,
                    mStampSignerConfig,
                    mSourceStampSigningCertificateLineage,
                    mMinSdkVersion,
                    mV1SigningEnabled,
                    mV2SigningEnabled,
                    mV3SigningEnabled,
                    mVerityEnabled,
                    mDebuggableApkPermitted,
                    mOtherSignersSignaturesPreserved,
                    mCreatedBy,
                    mSigningCertificateLineage,
                    mDigestAlgorithm);
            }

            /** Sets the signer configuration for the SourceStamp to be embedded in the APK. */
            public Builder setStampSignerConfig(SignerConfig stampSignerConfig)
            {
                mStampSignerConfig = stampSignerConfig;
                return this;
            }

            /**
 * Sets the source stamp {@link SigningCertificateLineage}. This structure provides proof of
 * signing certificate rotation for certificates previously used to sign source stamps.
 */
            public Builder setSourceStampSigningCertificateLineage(
                SigningCertificateLineage sourceStampSigningCertificateLineage)
            {
                mSourceStampSigningCertificateLineage = sourceStampSigningCertificateLineage;
                return this;
            }

            /**
 * Sets whether the APK should be signed using JAR signing (aka v1 signature scheme).
 *
 * <p>By default, the APK will be signed using this scheme.
 */
            public Builder setV1SigningEnabled(bool enabled)
            {
                mV1SigningEnabled = enabled;
                return this;
            }

            /**
 * Sets whether the APK should be signed using APK Signature Scheme v2 (aka v2 signature
 * scheme).
 *
 * <p>By default, the APK will be signed using this scheme.
 */
            public Builder setV2SigningEnabled(bool enabled)
            {
                mV2SigningEnabled = enabled;
                return this;
            }

            /**
 * Sets whether the APK should be signed using APK Signature Scheme v3 (aka v3 signature
 * scheme).
 *
 * <p>By default, the APK will be signed using this scheme.
 */
            public Builder setV3SigningEnabled(bool enabled)
            {
                mV3SigningEnabled = enabled;
                if (enabled)
                {
                    mV3SigningExplicitlyEnabled = true;
                }
                else
                {
                    mV3SigningExplicitlyDisabled = true;
                }

                return this;
            }

            /**
 * Sets whether the APK should be signed using the verity signature algorithm in the v2 and
 * v3 signature blocks.
 *
 * <p>By default, the APK will be signed using the verity signature algorithm for the v2 and
 * v3 signature schemes.
 */
            public Builder setVerityEnabled(bool enabled)
            {
                mVerityEnabled = enabled;
                return this;
            }

            /**
 * Sets whether the APK should be signed even if it is marked as debuggable ({@code
 * android:debuggable="true"} in its {@code AndroidManifest.xml}). For backward
 * compatibility reasons, the default value of this setting is {@code true}.
 *
 * <p>It is dangerous to sign debuggable APKs with production/release keys because Android
 * platform loosens security checks for such APKs. For example, arbitrary unauthorized code
 * may be executed in the context of such an app by anybody with ADB shell access.
 */
            public Builder setDebuggableApkPermitted(bool permitted)
            {
                mDebuggableApkPermitted = permitted;
                return this;
            }

            /**
 * Sets whether signatures produced by signers other than the ones configured in this engine
 * should be copied from the input APK to the output APK.
 *
 * <p>By default, signatures of other signers are omitted from the output APK.
 */
            public Builder setOtherSignersSignaturesPreserved(bool preserved)
            {
                mOtherSignersSignaturesPreserved = preserved;
                return this;
            }

            /** Sets the value of the {@code Created-By} field in JAR signature files. */
            public Builder setCreatedBy(String createdBy)
            {
                if (createdBy == null)
                {
                    throw new ArgumentNullException(nameof(createdBy));
                }

                mCreatedBy = createdBy;
                return this;
            }

            /**
 * Sets the {@link SigningCertificateLineage} to use with the v3 signature scheme. This
 * structure provides proof of signing certificate rotation linking {@link SignerConfig}
 * objects to previous ones.
 */
            public Builder setSigningCertificateLineage(
                SigningCertificateLineage signingCertificateLineage)
            {
                if (signingCertificateLineage != null)
                {
                    mV3SigningEnabled = true;
                    mSigningCertificateLineage = signingCertificateLineage;
                }

                return this;
            }

            public Builder setDigestAlgorithm(DigestAlgorithm digestAlgorithm)
            {
                mDigestAlgorithm = digestAlgorithm;
                return this;
            }
        }
    }
}