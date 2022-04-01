/*
 * Copyright (C) 2020 The Android Open Source Project
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
using SigningServer.Android;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.v2;
using SigningServer.Android.ApkSig.Internal.Apk.v3;
using SigningServer.Android.ApkSig.Internal.Apk.v4;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;

namespace SigningServer.Android.ApkSig.Internal.Apk.v4
{
    /**
 * APK Signature Scheme V4 signer. V4 scheme file contains 2 mandatory fields - used during
 * installation. And optional verity tree - has to be present during session commit.
 * <p>
 * The fields:
 * <p>
 * 1. hashingInfo - verity root hash and hashing info,
 * 2. signingInfo - certificate, public key and signature,
 * For more details see V4Signature.
 * </p>
 * (optional) verityTree: int size prepended bytes of the verity hash tree.
 * <p>
 * TODO(schfan): Add v4 unit tests
 */
    public abstract class V4SchemeSigner
    {
        /**
     * Hidden constructor to prevent instantiation.
     */
        private V4SchemeSigner()
        {
        }

        /**
     * Based on a public key, return a signing algorithm that supports verity.
     */
        public static List<SignatureAlgorithm> getSuggestedSignatureAlgorithms(PublicKey signingKey,
            int minSdkVersion, bool apkSigningBlockPaddingSupported,
            bool deterministicDsaSigning)

        {
            List<SignatureAlgorithm> algorithms = V3SchemeSigner.getSuggestedSignatureAlgorithms(
                signingKey, minSdkVersion,
                apkSigningBlockPaddingSupported, deterministicDsaSigning);

            // Keeping only supported algorithms.
            algorithms = algorithms
                .Where(algorithm => isSupported(algorithm.getContentDigestAlgorithm(), false))
                .ToList();

            return algorithms;
        }

        /**
         * Compute hash tree and generate v4 signature for a given APK. Write the serialized data to
         * output file.
         */
        public static void generateV4Signature(
            DataSource apkContent, ApkSigningBlockUtils.SignerConfig signerConfig, FileInfo outputFile)

        {
            Tuple<V4Signature, byte[]> pair = generateV4Signature(apkContent, signerConfig);
            try
            {
                using (var output = outputFile.OpenWrite())
                {
                    pair.Item1.writeTo(output);
                    V4Signature.writeBytes(output, pair.Item2);
                }
            }
            catch (IOException e)
            {
                outputFile.Delete();
                throw e;
            }
        }

        /** Generate v4 signature and hash tree for a given APK. */
        public static Tuple<V4Signature, byte[]> generateV4Signature(
            DataSource apkContent,
            ApkSigningBlockUtils.SignerConfig signerConfig)

        {
            // Salt has to stay empty for fs-verity compatibility.
            byte[] salt = null;
            // Not used by apksigner.
            byte[] additionalData = null;

            long fileSize = apkContent.size();

            // Obtaining first supported digest from v2/v3 blocks (SHA256 or SHA512).
            byte[] apkDigest = getApkDigest(apkContent);

            // Obtaining the merkle tree and the root hash in verity format.
            ApkSigningBlockUtils.VerityTreeAndDigest verityContentDigestInfo =
                ApkSigningBlockUtils.computeChunkVerityTreeAndDigest(apkContent);

            ContentDigestAlgorithm verityContentDigestAlgorithm =
                verityContentDigestInfo.contentDigestAlgorithm;
            byte[] rootHash = verityContentDigestInfo.rootHash;
            byte[] tree = verityContentDigestInfo.tree;

            Tuple<int, Byte>
                hashingAlgorithmBlockSizePair = convertToV4HashingInfo(
                    verityContentDigestAlgorithm);
            V4Signature.HashingInfo hashingInfo = new V4Signature.HashingInfo(
                hashingAlgorithmBlockSizePair.Item1, hashingAlgorithmBlockSizePair.Item2,
                salt, rootHash);

            // Generating SigningInfo and combining everything into V4Signature.
            V4Signature signature;
            try
            {
                signature = generateSignature(signerConfig, hashingInfo, apkDigest, additionalData,
                    fileSize);
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException("Signer failed", e);
            }

            return Tuple.Create(signature, tree);
        }

        private static V4Signature generateSignature(
            ApkSigningBlockUtils.SignerConfig signerConfig,
            V4Signature.HashingInfo hashingInfo,
            byte[] apkDigest, byte[] additionaData, long fileSize)

        {
            if (signerConfig.certificates.Count == 0)
            {
                throw new CryptographicException("No certificates configured for signer");
            }

            if (signerConfig.certificates.Count != 1)
            {
                throw new CryptographicException("Should only have one certificate");
            }

            // Collecting data for signing.
            PublicKey publicKey = signerConfig.certificates[0].getPublicKey();

            List<byte[]> encodedCertificates = ApkSigningBlockUtils.encodeCertificates(signerConfig.certificates);
            byte[] encodedCertificate = encodedCertificates[0];

            V4Signature.SigningInfo signingInfoNoSignature = new V4Signature.SigningInfo(apkDigest,
                encodedCertificate, additionaData, publicKey.getEncoded(), -1, null);

            byte[] data = V4Signature.getSignedData(fileSize, hashingInfo,
                signingInfoNoSignature);

            // Signing.
            List<Tuple<int, byte[]>> signatures =
                ApkSigningBlockUtils.generateSignaturesOverData(signerConfig, data);
            if (signatures.Count != 1)
            {
                throw new CryptographicException("Should only be one signature generated");
            }

            int signatureAlgorithmId = signatures[0].Item1;
            byte[] signature = signatures[0].Item2;

            V4Signature.SigningInfo signingInfo = new V4Signature.SigningInfo(apkDigest,
                encodedCertificate, additionaData, publicKey.getEncoded(), signatureAlgorithmId,
                signature);

            return new V4Signature(V4Signature.CURRENT_VERSION, hashingInfo.toByteArray(),
                signingInfo.toByteArray());
        }

        // Get digest by parsing the V2/V3-signed apk and choosing the first digest of supported type.
        private static byte[] getApkDigest(DataSource apk)
        {
            ZipSections zipSections;
            try
            {
                zipSections = ApkUtils.findZipSections(apk);
            }
            catch (ZipFormatException e)
            {
                throw new IOException("Malformed APK: not a ZIP archive", e);
            }

            CryptographicException v3Exception;
            try
            {
                return getBestV3Digest(apk, zipSections);
            }
            catch (CryptographicException e)
            {
                v3Exception = e;
            }

            CryptographicException v2Exception;
            try
            {
                return getBestV2Digest(apk, zipSections);
            }
            catch (CryptographicException e)
            {
                v2Exception = e;
            }

            throw new IOException(
                "Failed to obtain v2/v3 digest, v3 exception: " + v3Exception + ", v2 exception: "
                + v2Exception);
        }

        private static byte[] getBestV3Digest(DataSource apk, ZipSections zipSections)
        {
            ISet<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<ContentDigestAlgorithm>(1);
            ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
            try
            {
                SignatureInfo signatureInfo =
                    ApkSigningBlockUtils.findSignature(apk, zipSections,
                        V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID, result);
                ByteBuffer apkSignatureSchemeV3Block = signatureInfo.signatureBlock;
                V3SchemeVerifier.parseSigners(apkSignatureSchemeV3Block, contentDigestsToVerify,
                    result);
            }
            catch (Exception e)
            {
                throw new CryptographicException("Failed to extract and parse v3 block", e);
            }

            if (result.signers.Count != 1)
            {
                throw new CryptographicException("Should only have one signer, errors: " + result.getErrors());
            }

            ApkSigningBlockUtils.Result.SignerInfo signer = result.signers[0];
            if (signer.containsErrors())
            {
                throw new CryptographicException("Parsing failed: " + signer.getErrors());
            }

            List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> contentDigests =
                result.signers[0].contentDigests;
            return pickBestDigest(contentDigests);
        }

        private static byte[] getBestV2Digest(DataSource apk, ZipSections zipSections)
        {
            ISet<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<ContentDigestAlgorithm>(1);
            ISet<int> foundApkSigSchemeIds = new HashSet<int>(1);
            ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2);
            try
            {
                SignatureInfo signatureInfo =
                    ApkSigningBlockUtils.findSignature(apk, zipSections,
                        V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID, result);
                ByteBuffer apkSignatureSchemeV2Block = signatureInfo.signatureBlock;
                V2SchemeVerifier.parseSigners(
                    apkSignatureSchemeV2Block,
                    contentDigestsToVerify,
                    new Dictionary<int, string>(),
                    foundApkSigSchemeIds,
                    int.MaxValue,
                    int.MaxValue,
                    result);
            }
            catch (Exception e)
            {
                throw new CryptographicException("Failed to extract and parse v2 block", e);
            }

            if (result.signers.Count != 1)
            {
                throw new CryptographicException("Should only have one signer, errors: " + result.getErrors());
            }

            ApkSigningBlockUtils.Result.SignerInfo signer = result.signers[0];
            if (signer.containsErrors())
            {
                throw new CryptographicException("Parsing failed: " + signer.getErrors());
            }

            List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> contentDigests =
                signer.contentDigests;
            return pickBestDigest(contentDigests);
        }

        private static byte[] pickBestDigest(List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> contentDigests)
        {
            if (contentDigests == null || contentDigests.Count == 0)
            {
                throw new CryptographicException("Should have at least one digest");
            }

            int bestAlgorithmOrder = -1;
            byte[] bestDigest = null;
            foreach (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest contentDigest in contentDigests)
            {
                SignatureAlgorithm signatureAlgorithm =
                    SignatureAlgorithm.findById(contentDigest.getSignatureAlgorithmId());
                ContentDigestAlgorithm contentDigestAlgorithm =
                    signatureAlgorithm.getContentDigestAlgorithm();
                if (!isSupported(contentDigestAlgorithm, true))
                {
                    continue;
                }

                int algorithmOrder = digestAlgorithmSortingOrder(contentDigestAlgorithm);
                if (bestAlgorithmOrder < algorithmOrder)
                {
                    bestAlgorithmOrder = algorithmOrder;
                    bestDigest = contentDigest.getValue();
                }
            }

            if (bestDigest == null)
            {
                throw new CryptographicException("Failed to find a supported digest in the source APK");
            }

            return bestDigest;
        }

        public static int digestAlgorithmSortingOrder(ContentDigestAlgorithm contentDigestAlgorithm)
        {
            if (contentDigestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA256)
                return 0;
            if (contentDigestAlgorithm == ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)
                return 1;
            if (contentDigestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA512)
                return 2;
            return -1;
        }

        private static bool isSupported(ContentDigestAlgorithm contentDigestAlgorithm, bool forV3Digest)
        {
            if (contentDigestAlgorithm == null)
            {
                return false;
            }

            if (contentDigestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA256
                || contentDigestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA512
                || (forV3Digest
                    && contentDigestAlgorithm == ContentDigestAlgorithm.VERITY_CHUNKED_SHA256))
            {
                return true;
            }

            return false;
        }

        private static Tuple<int, Byte> convertToV4HashingInfo(ContentDigestAlgorithm algorithm)
        {
            if (algorithm == ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)
            {
                return Tuple.Create(V4Signature.HASHING_ALGORITHM_SHA256,
                    V4Signature.LOG2_BLOCK_SIZE_4096_BYTES);
            }

            throw new CryptographicException(
                "Invalid hash algorithm, only SHA2-256 over 4 KB chunks supported.");
        }
    }
}