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
using System.Security.Cryptography;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;
using static SigningServer.Android.ApkSig.Internal.Apk.ApkSigningBlockUtilsLite;

namespace SigningServer.Android.ApkSig.Internal.Apk.Stamp
{
    /**
     * Source Stamp verifier.
     *
     * <p>V1 of the source stamp verifies the stamp signature of at most one signature scheme.
     */
    public abstract class V1SourceStampVerifier
    {
        /** Hidden constructor to prevent instantiation. */
        private V1SourceStampVerifier()
        {
        }

        /**
         * Verifies the provided APK's SourceStamp signatures and returns the result of verification.
         * The APK must be considered verified only if {@link ApkSigningBlockUtils.Result#verified} is
         * {@code true}. If verification fails, the result will contain errors -- see {@link
         * ApkSigningBlockUtils.Result#getErrors()}.
         *
         * @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
         *     required cryptographic algorithm implementation is missing
         * @throws ApkSigningBlockUtils.SignatureNotFoundException if no SourceStamp signatures are
         *     found
         * @throws IOException if an I/O error occurs when reading the APK
         */
        public static ApkSigningBlockUtils.Result verify(
            DataSource apk,
            ZipSections zipSections,
            byte[] sourceStampCertificateDigest,
            Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests,
            int minSdkVersion,
            int maxSdkVersion)
        {
            ApkSigningBlockUtils.Result result =
                new ApkSigningBlockUtils.Result(ApkSigningBlockUtils.VERSION_SOURCE_STAMP);
            SignatureInfo signatureInfo =
                ApkSigningBlockUtils.findSignature(
                    apk, zipSections, SourceStampConstants.V1_SOURCE_STAMP_BLOCK_ID, result);

            verify(
                signatureInfo.signatureBlock,
                sourceStampCertificateDigest,
                apkContentDigests,
                minSdkVersion,
                maxSdkVersion,
                result);
            return result;
        }

        /**
     * Verifies the provided APK's SourceStamp signatures and outputs the results into the provided
     * {@code result}. APK is considered verified only if there are no errors reported in the {@code
     * result}. See {@link #verify(DataSource, ApkUtils.ZipSections, byte[], Map, int, int)} for
     * more information about the contract of this method.
     */
        private static void verify(
            ByteBuffer sourceStampBlock,
            byte[] sourceStampCertificateDigest,
            Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests,
            int minSdkVersion,
            int maxSdkVersion,
            ApkSigningBlockUtils.Result result)
        {
            ApkSigningBlockUtils.Result.SignerInfo signerInfo =
                new ApkSigningBlockUtils.Result.SignerInfo();
            result.signers.Add(signerInfo);
            try
            {
                ByteBuffer sourceStampBlockData =
                    ApkSigningBlockUtils.getLengthPrefixedSlice(sourceStampBlock);
                byte[] digestBytes =
                    encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                        getApkDigests(apkContentDigests));
                SourceStampVerifier.verifyV1SourceStamp(
                    sourceStampBlockData,
                    signerInfo,
                    digestBytes,
                    sourceStampCertificateDigest,
                    minSdkVersion,
                    maxSdkVersion);
                result.verified = !result.containsErrors() && !result.containsWarnings();
            }
            catch (CryptographicException e)
            {
                throw new InvalidOperationException("Failed to obtain X.509 CertificateFactory", e);
            }
            catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
            {
                signerInfo.addWarning(ApkVerifier.Issue.SOURCE_STAMP_MALFORMED_SIGNATURE);
            }
        }

        private static List<Tuple<int, byte[]>> getApkDigests(
            Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests)
        {
            List<Tuple<int, byte[]>> digests = new List<Tuple<int, byte[]>>();
            foreach (var apkContentDigest in apkContentDigests)
            {
                digests.Add(Tuple.Create(apkContentDigest.Key.getId(), apkContentDigest.Value));
            }

            digests.Sort((a, b) => a.Item1.CompareTo(b.Item1));
            return digests;
        }
    }
}