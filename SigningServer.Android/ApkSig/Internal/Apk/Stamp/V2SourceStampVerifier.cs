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
     * <p>V2 of the source stamp verifies the stamp signature of more than one signature schemes.
     */
    public abstract class V2SourceStampVerifier
    {
        /** Hidden constructor to prevent instantiation. */
        private V2SourceStampVerifier()
        {
        }

        /**
         * Verifies the provided APK's SourceStamp signatures and returns the result of verification.
         * The APK must be considered verified only if {@link ApkSigResult#verified} is
         * {@code true}. If verification fails, the result will contain errors -- see {@link
         * ApkSigResult#getErrors()}.
         *
         * @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
         *     required cryptographic algorithm implementation is missing
         * @throws SignatureNotFoundException if no SourceStamp signatures are
         *     found
         * @throws IOException if an I/O error occurs when reading the APK
         */
        public static ApkSigResult verify(
            DataSource apk,
            ZipSections zipSections,
            byte[] sourceStampCertificateDigest,
            Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests,
            int minSdkVersion,
            int maxSdkVersion)
        {
            ApkSigResult result =
                new ApkSigResult(Constants.VERSION_SOURCE_STAMP);
            SignatureInfo signatureInfo =
                ApkSigningBlockUtilsLite.findSignature(
                    apk, zipSections, SourceStampConstants.V2_SOURCE_STAMP_BLOCK_ID);

            verify(
                signatureInfo.signatureBlock,
                sourceStampCertificateDigest,
                signatureSchemeApkContentDigests,
                minSdkVersion,
                maxSdkVersion,
                result);
            return result;
        }

        /**
     * Verifies the provided APK's SourceStamp signatures and outputs the results into the provided
     * {@code result}. APK is considered verified only if there are no errors reported in the {@code
     * result}. See {@link #verify(DataSource, ZipSections, byte[], Map, int, int)} for
     * more information about the contract of this method.
     */
        private static void verify(
            ByteBuffer sourceStampBlock,
            byte[] sourceStampCertificateDigest,
            Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests,
            int minSdkVersion,
            int maxSdkVersion,
            ApkSigResult result)
        {
            ApkSignerInfo signerInfo = new ApkSignerInfo();
            result.mSigners.Add(signerInfo);
            try
            {
                ByteBuffer sourceStampBlockData =
                    ApkSigningBlockUtilsLite.getLengthPrefixedSlice(sourceStampBlock);
                SourceStampVerifier.verifyV2SourceStamp(
                    sourceStampBlockData,
                    signerInfo,
                    getSignatureSchemeDigests(signatureSchemeApkContentDigests),
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
                signerInfo.addWarning(ApkVerificationIssue.SOURCE_STAMP_MALFORMED_SIGNATURE);
            }
        }

        private static Dictionary<int, byte[]> getSignatureSchemeDigests(
            Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests)
        {
            Dictionary<int, byte[]> digests = new Dictionary<int, byte[]>();
            foreach (var signatureSchemeApkContentDigest in signatureSchemeApkContentDigests)
            {
                List<Tuple<int, byte[]>> apkDigests =
                    getApkDigests(signatureSchemeApkContentDigest.Value);
                digests.Add(
                    signatureSchemeApkContentDigest.Key,
                    encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(apkDigests));
            }

            return digests;
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