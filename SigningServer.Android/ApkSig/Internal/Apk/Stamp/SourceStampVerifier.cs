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
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Util;
using static SigningServer.Android.ApkSig.Internal.Apk.ApkSigningBlockUtilsLite;

namespace SigningServer.Android.ApkSig.Internal.Apk.Stamp
{
    /**
     * Source Stamp verifier.
     *
     * <p>SourceStamp improves traceability of apps with respect to unauthorized distribution.
     *
     * <p>The stamp is part of the APK that is protected by the signing block.
     *
     * <p>The APK contents hash is signed using the stamp key, and is saved as part of the signing
     * block.
     */
    class SourceStampVerifier
    {
        /** Hidden constructor to prevent instantiation. */
        private SourceStampVerifier()
        {
        }

        /**
         * Parses the SourceStamp block and populates the {@code result}.
         *
         * <p>This verifies signatures over digest provided.
         *
         * <p>This method adds one or more errors to the {@code result} if a verification error is
         * expected to be encountered on an Android platform version in the {@code [minSdkVersion,
         * maxSdkVersion]} range.
         */
        public static void verifyV1SourceStamp(
            ByteBuffer sourceStampBlockData,
            ApkSignerInfo result,
            byte[] apkDigest,
            byte[] sourceStampCertificateDigest,
            int minSdkVersion,
            int maxSdkVersion)
        {
            X509Certificate sourceStampCertificate =
                verifySourceStampCertificate(
                    sourceStampBlockData, sourceStampCertificateDigest, result);
            if (result.containsWarnings() || result.containsErrors())
            {
                return;
            }

            ByteBuffer apkDigestSignatures = getLengthPrefixedSlice(sourceStampBlockData);
            verifySourceStampSignature(
                apkDigest,
                minSdkVersion,
                maxSdkVersion,
                sourceStampCertificate,
                apkDigestSignatures,
                result);
        }

        /**
     * Parses the SourceStamp block and populates the {@code result}.
     *
     * <p>This verifies signatures over digest of multiple signature schemes provided.
     *
     * <p>This method adds one or more errors to the {@code result} if a verification error is
     * expected to be encountered on an Android platform version in the {@code [minSdkVersion,
     * maxSdkVersion]} range.
     */
        public static void verifyV2SourceStamp(
            ByteBuffer sourceStampBlockData,
            ApkSignerInfo result,
            Dictionary<int, byte[]> signatureSchemeApkDigests,
            byte[] sourceStampCertificateDigest,
            int? minSdkVersion,
            int maxSdkVersion)
        {
            X509Certificate sourceStampCertificate =
                verifySourceStampCertificate(
                    sourceStampBlockData, sourceStampCertificateDigest, result);
            if (result.containsWarnings() || result.containsErrors())
            {
                return;
            }

            // Parse signed signature schemes block.
            ByteBuffer signedSignatureSchemes = getLengthPrefixedSlice(sourceStampBlockData);
            Dictionary<int, ByteBuffer> signedSignatureSchemeData = new Dictionary<int, ByteBuffer>();
            while (signedSignatureSchemes.hasRemaining())
            {
                ByteBuffer signedSignatureScheme = getLengthPrefixedSlice(signedSignatureSchemes);
                int signatureSchemeId = signedSignatureScheme.getInt();
                ByteBuffer apkDigestSignatures = getLengthPrefixedSlice(signedSignatureScheme);
                signedSignatureSchemeData.Add(signatureSchemeId, apkDigestSignatures);
            }

            foreach (var signatureSchemeApkDigest in signatureSchemeApkDigests)
            {
                if (!signedSignatureSchemeData.ContainsKey(signatureSchemeApkDigest.Key))
                {
                    result.addWarning(ApkVerificationIssue.SOURCE_STAMP_NO_SIGNATURE);
                    return;
                }

                verifySourceStampSignature(
                    signatureSchemeApkDigest.Value,
                    minSdkVersion,
                    maxSdkVersion,
                    sourceStampCertificate,
                    signedSignatureSchemeData[signatureSchemeApkDigest.Key],
                    result);
                if (result.containsWarnings() || result.containsErrors())
                {
                    return;
                }
            }

            if (sourceStampBlockData.hasRemaining())
            {
                // The stamp block contains some additional attributes.
                ByteBuffer stampAttributeData = getLengthPrefixedSlice(sourceStampBlockData);
                ByteBuffer stampAttributeDataSignatures = getLengthPrefixedSlice(sourceStampBlockData);

                byte[] stampAttributeBytes = new byte[stampAttributeData.remaining()];
                stampAttributeData.get(stampAttributeBytes);
                stampAttributeData.flip();

                verifySourceStampSignature(stampAttributeBytes, minSdkVersion, maxSdkVersion,
                    sourceStampCertificate, stampAttributeDataSignatures, result);
                if (result.containsErrors() || result.containsWarnings())
                {
                    return;
                }

                parseStampAttributes(stampAttributeData, sourceStampCertificate, result);
            }
        }

        private static X509Certificate verifySourceStampCertificate(
            ByteBuffer sourceStampBlockData,
            byte[] sourceStampCertificateDigest,
            ApkSignerInfo result)
        {
            // Parse the SourceStamp certificate.
            byte[] sourceStampEncodedCertificate = readLengthPrefixedByteArray(sourceStampBlockData);
            X509Certificate sourceStampCertificate;
            try
            {
                sourceStampCertificate = new X509Certificate(sourceStampEncodedCertificate);
            }
            catch (CryptographicException e)
            {
                result.addWarning(ApkVerificationIssue.SOURCE_STAMP_MALFORMED_CERTIFICATE, e);
                return null;
            }

            // Wrap the cert so that the result's getEncoded returns exactly the original encoded
            // form. Without this, getEncoded may return a different form from what was stored in
            // the signature. This is because some X509Certificate(Factory) implementations
            // re-encode certificates.
            sourceStampCertificate =
                new GuaranteedEncodedFormX509Certificate(
                    sourceStampCertificate, sourceStampEncodedCertificate);
            result.certs.Add(sourceStampCertificate);
            // Verify the SourceStamp certificate found in the signing block is the same as the
            // SourceStamp certificate found in the APK.
            using (var messageDigest = SHA256.Create())
            {
                byte[] sourceStampBlockCertificateDigest = messageDigest.ComputeHash(sourceStampEncodedCertificate, 0,
                    sourceStampEncodedCertificate.Length);
                if (!sourceStampCertificateDigest.SequenceEqual(sourceStampBlockCertificateDigest))
                {
                    result.addWarning(
                        ApkVerificationIssue
                            .SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK,
                        toHex(sourceStampBlockCertificateDigest),
                        toHex(sourceStampCertificateDigest));
                    return null;
                }
            }

            return sourceStampCertificate;
        }

        private static void verifySourceStampSignature(
            byte[] data,
            int? minSdkVersion,
            int maxSdkVersion,
            X509Certificate sourceStampCertificate,
            ByteBuffer signatures,
            ApkSignerInfo result)
        {
            // Parse the signatures block and identify supported signatures
            int signatureCount = 0;
            List<ApkSupportedSignature> supportedSignatures = new List<ApkSupportedSignature>(1);
            while (signatures.hasRemaining())
            {
                signatureCount++;
                try
                {
                    ByteBuffer signature = getLengthPrefixedSlice(signatures);
                    int sigAlgorithmId = signature.getInt();
                    byte[] sigBytes = readLengthPrefixedByteArray(signature);
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(sigAlgorithmId);
                    if (signatureAlgorithm == null)
                    {
                        result.addWarning(
                            ApkVerificationIssue.SOURCE_STAMP_UNKNOWN_SIG_ALGORITHM,
                            sigAlgorithmId);
                        continue;
                    }

                    supportedSignatures.Add(
                        new ApkSupportedSignature(signatureAlgorithm, sigBytes));
                }
                catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
                {
                    result.addWarning(
                        ApkVerificationIssue.SOURCE_STAMP_MALFORMED_SIGNATURE, signatureCount);
                    return;
                }
            }

            if (supportedSignatures.Count == 0)
            {
                result.addWarning(ApkVerificationIssue.SOURCE_STAMP_NO_SIGNATURE);
                return;
            }

            // Verify signatures over digests using the SourceStamp's certificate.
            List<ApkSupportedSignature> signaturesToVerify;
            try
            {
                signaturesToVerify =
                    getSignaturesToVerify(
                        supportedSignatures, minSdkVersion, maxSdkVersion, true);
            }
            catch (NoApkSupportedSignaturesException e)
            {
                // To facilitate debugging capture the signature algorithms and resulting exception in
                // the warning.
                StringBuilder signatureAlgorithms = new StringBuilder();
                foreach (ApkSupportedSignature supportedSignature in supportedSignatures)
                {
                    if (signatureAlgorithms.Length > 0)
                    {
                        signatureAlgorithms.Append(", ");
                    }

                    signatureAlgorithms.Append(supportedSignature.algorithm);
                }

                result.addWarning(ApkVerificationIssue.SOURCE_STAMP_NO_SUPPORTED_SIGNATURE,
                    signatureAlgorithms.ToString(), e);
                return;
            }

            foreach (ApkSupportedSignature signature in signaturesToVerify)
            {
                SignatureAlgorithm signatureAlgorithm = signature.algorithm;
                String jcaSignatureAlgorithm =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams().Item1;
                AlgorithmParameterSpec jcaSignatureAlgorithmParams =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams().Item2;
                PublicKey publicKey = sourceStampCertificate.getPublicKey();
                try
                {
                    Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                    sig.initVerify(publicKey);
                    if (jcaSignatureAlgorithmParams != null)
                    {
                        sig.setParameter(jcaSignatureAlgorithmParams);
                    }
                    
                    sig.update(data);
                    byte[] sigBytes = signature.signature;
                    if (!sig.verify(sigBytes))
                    {
                        result.addWarning(
                            ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY, signatureAlgorithm);
                        return;
                    }
                }
                catch (Exception e)
                {
                    result.addWarning(
                        ApkVerificationIssue.SOURCE_STAMP_VERIFY_EXCEPTION, signatureAlgorithm, e);
                    return;
                }
            }
        }

        private static void parseStampAttributes(ByteBuffer stampAttributeData,
            X509Certificate sourceStampCertificate, ApkSignerInfo result)
        {
            ByteBuffer stampAttributes = getLengthPrefixedSlice(stampAttributeData);

            int stampAttributeCount = 0;
            while (stampAttributes.hasRemaining())
            {
                stampAttributeCount++;
                try
                {
                    ByteBuffer attribute = getLengthPrefixedSlice(stampAttributes);
                    int id = attribute.getInt();
                    byte[] value = ByteBufferUtils.toByteArray(attribute);
                    if (id == SourceStampConstants.PROOF_OF_ROTATION_ATTR_ID)
                    {
                        readStampCertificateLineage(value, sourceStampCertificate, result);
                    }
                    else
                    {
                        result.addWarning(ApkVerificationIssue.SOURCE_STAMP_UNKNOWN_ATTRIBUTE, id);
                    }
                }
                catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
                {
                    result.addWarning(ApkVerificationIssue.SOURCE_STAMP_MALFORMED_ATTRIBUTE,
                        stampAttributeCount);
                    return;
                }
            }
        }

        private static void readStampCertificateLineage(byte[] lineageBytes,
            X509Certificate sourceStampCertificate, ApkSignerInfo result)
        {
            try
            {
                // SourceStampCertificateLineage is verified when built
                List<SourceStampCertificateLineage.SigningCertificateNode> nodes =
                    SourceStampCertificateLineage.readSigningCertificateLineage(
                        ByteBuffer.wrap(lineageBytes).order(ByteOrder.LITTLE_ENDIAN));
                for (int i = 0; i < nodes.Count; i++)
                {
                    result.certificateLineage.Add(nodes[i].signingCert);
                }

                // Make sure that the last cert in the chain matches this signer cert
                if (!sourceStampCertificate.Equals(
                        result.certificateLineage[result.certificateLineage.Count - 1]))
                {
                    result.addWarning(ApkVerificationIssue.SOURCE_STAMP_POR_CERT_MISMATCH);
                }
            }
            catch (SecurityException e)
            {
                result.addWarning(ApkVerificationIssue.SOURCE_STAMP_POR_DID_NOT_VERIFY);
            }
            catch (ArgumentException e)
            {
                result.addWarning(ApkVerificationIssue.SOURCE_STAMP_POR_CERT_MISMATCH);
            }
            catch (Exception e)
            {
                result.addWarning(ApkVerificationIssue.SOURCE_STAMP_MALFORMED_LINEAGE);
            }
        }
    }
}