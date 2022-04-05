/*
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
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;

namespace SigningServer.Android.ApkSig.Internal.Apk.v2
{
    /**
     * APK Signature Scheme v2 verifier.
     *
     * <p>APK Signature Scheme v2 is a whole-file signature scheme which aims to protect every single
     * bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
     * uncompressed contents of ZIP entries.
     *
     * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2</a>
     */
    public static class V2SchemeVerifier
    {
        /**
     * Verifies the provided APK's APK Signature Scheme v2 signatures and returns the result of
     * verification. The APK must be considered verified only if
     * {@link ApkSigningBlockUtils.Result#verified} is
     * {@code true}. If verification fails, the result will contain errors -- see
     * {@link ApkSigningBlockUtils.Result#getErrors()}.
     *
     * <p>Verification succeeds iff the APK's APK Signature Scheme v2 signatures are expected to
     * verify on all Android platform versions in the {@code [minSdkVersion, maxSdkVersion]} range.
     * If the APK's signature is expected to not verify on any of the specified platform versions,
     * this method returns a result with one or more errors and whose
     * {@code Result.verified == false}, or this method throws an exception.
     *
     * @throws ApkFormatException if the APK is malformed
     * @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
     *         required cryptographic algorithm implementation is missing
     * @throws ApkSigningBlockUtils.SignatureNotFoundException if no APK Signature Scheme v2
     * signatures are found
     * @throws IOException if an I/O error occurs when reading the APK
     */
        public static ApkSigningBlockUtils.Result verify(
            RunnablesExecutor executor,
            DataSource apk,
            ZipSections zipSections,
            Dictionary<int, String> supportedApkSigSchemeNames,
            ISet<int> foundSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion)

        {
            ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2);
            SignatureInfo signatureInfo =
                ApkSigningBlockUtils.findSignature(apk, zipSections,
                    V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID, result);

            DataSource beforeApkSigningBlock = apk.slice(0, signatureInfo.apkSigningBlockOffset);
            DataSource centralDir =
                apk.slice(
                    signatureInfo.centralDirOffset,
                    signatureInfo.eocdOffset - signatureInfo.centralDirOffset);
            ByteBuffer eocd = signatureInfo.eocd;

            verify(executor,
                beforeApkSigningBlock,
                signatureInfo.signatureBlock,
                centralDir,
                eocd,
                supportedApkSigSchemeNames,
                foundSigSchemeIds,
                minSdkVersion,
                maxSdkVersion,
                result);
            return result;
        }

        /**
     * Verifies the provided APK's v2 signatures and outputs the results into the provided
     * {@code result}. APK is considered verified only if there are no errors reported in the
     * {@code result}. See {@link #verify(RunnablesExecutor, DataSource, ApkUtils.ZipSections, Map,
     * Set, int, int)} for more information about the contract of this method.
     *
     * @param result result populated by this method with interesting information about the APK,
     *        such as information about signers, and verification errors and warnings.
     */
        private static void verify(
            RunnablesExecutor executor,
            DataSource beforeApkSigningBlock,
            ByteBuffer apkSignatureSchemeV2Block,
            DataSource centralDir,
            ByteBuffer eocd,
            Dictionary<int, String> supportedApkSigSchemeNames,
            ISet<int> foundSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion,
            ApkSigningBlockUtils.Result result)

        {
            ISet<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<ContentDigestAlgorithm>(1);
            parseSigners(
                apkSignatureSchemeV2Block,
                contentDigestsToVerify,
                supportedApkSigSchemeNames,
                foundSigSchemeIds,
                minSdkVersion,
                maxSdkVersion,
                result);
            if (result.containsErrors())
            {
                return;
            }

            ApkSigningBlockUtils.verifyIntegrity(
                executor, beforeApkSigningBlock, centralDir, eocd, contentDigestsToVerify, result);
            if (!result.containsErrors())
            {
                result.verified = true;
            }
        }

        /**
     * Parses each signer in the provided APK Signature Scheme v2 block and populates corresponding
     * {@code signerInfos} of the provided {@code result}.
     *
     * <p>This verifies signatures over {@code signed-data} block contained in each signer block.
     * However, this does not verify the integrity of the rest of the APK but rather simply reports
     * the expected digests of the rest of the APK (see {@code contentDigestsToVerify}).
     *
     * <p>This method adds one or more errors to the {@code result} if a verification error is
     * expected to be encountered on an Android platform version in the
     * {@code [minSdkVersion, maxSdkVersion]} range.
     */
        public static void parseSigners(
            ByteBuffer apkSignatureSchemeV2Block,
            ISet<ContentDigestAlgorithm> contentDigestsToVerify,
            Dictionary<int, String> supportedApkSigSchemeNames,
            ISet<int> foundApkSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion,
            ApkSigningBlockUtils.Result result)
        {
            ByteBuffer signers;
            try
            {
                signers = ApkSigningBlockUtils.getLengthPrefixedSlice(apkSignatureSchemeV2Block);
            }
            catch
                (ApkFormatException e)
            {
                result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_SIGNERS);
                return;
            }

            if (!signers.hasRemaining())
            {
                result.addError(ApkVerifier.Issue.V2_SIG_NO_SIGNERS);
                return;
            }

            int signerCount = 0;
            while (signers.hasRemaining())
            {
                int signerIndex = signerCount;
                signerCount++;
                ApkSigningBlockUtils.Result.SignerInfo signerInfo =
                    new ApkSigningBlockUtils.Result.SignerInfo();
                signerInfo.index = signerIndex;
                result.signers.Add(signerInfo);
                try
                {
                    ByteBuffer signer = ApkSigningBlockUtils.getLengthPrefixedSlice(signers);
                    parseSigner(
                        signer,
                        signerInfo,
                        contentDigestsToVerify,
                        supportedApkSigSchemeNames,
                        foundApkSigSchemeIds,
                        minSdkVersion,
                        maxSdkVersion);
                }
                catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
                {
                    signerInfo.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_SIGNER);
                    return;
                }
            }
        }

        /**
 * Parses the provided signer block and populates the {@code result}.
 *
 * <p>This verifies signatures over {@code signed-data} contained in this block but does not
 * verify the integrity of the rest of the APK. To facilitate APK integrity verification, this
 * method adds the {@code contentDigestsToVerify}. These digests can then be used to verify the
 * integrity of the APK.
 *
 * <p>This method adds one or more errors to the {@code result} if a verification error is
 * expected to be encountered on an Android platform version in the
 * {@code [minSdkVersion, maxSdkVersion]} range.
 */
        private static void parseSigner(
            ByteBuffer signerBlock,
            ApkSigningBlockUtils.Result.SignerInfo result,
            ISet<ContentDigestAlgorithm> contentDigestsToVerify,
            Dictionary<int, String> supportedApkSigSchemeNames,
            ISet<int> foundApkSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion)

        {
            ByteBuffer signedData = ApkSigningBlockUtils.getLengthPrefixedSlice(signerBlock);
            byte[] signedDataBytes = new byte[signedData.remaining()];
            signedData.get(signedDataBytes);
            signedData.flip();
            result.signedData = signedDataBytes;

            ByteBuffer signatures = ApkSigningBlockUtils.getLengthPrefixedSlice(signerBlock);
            byte[] publicKeyBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(signerBlock);

            // Parse the signatures block and identify supported signatures
            int signatureCount = 0;
            List<ApkSigningBlockUtils.SupportedSignature> supportedSignatures =
                new List<ApkSigningBlockUtils.SupportedSignature>(1);
            while (signatures.hasRemaining())
            {
                signatureCount++;
                try
                {
                    ByteBuffer signature = ApkSigningBlockUtils.getLengthPrefixedSlice(signatures);
                    int sigAlgorithmId = signature.getInt();
                    byte[] sigBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(signature);
                    result.signatures.Add(
                        new ApkSigningBlockUtils.Result.SignerInfo.Signature(
                            sigAlgorithmId, sigBytes));
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(sigAlgorithmId);
                    if (signatureAlgorithm == null)
                    {
                        result.addWarning(ApkVerifier.Issue.V2_SIG_UNKNOWN_SIG_ALGORITHM, sigAlgorithmId);
                        continue;
                    }

                    supportedSignatures.Add(
                        new ApkSigningBlockUtils.SupportedSignature(signatureAlgorithm, sigBytes));
                }
                catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
                {
                    result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_SIGNATURE, signatureCount);
                    return;
                }
            }

            if (result.signatures.Count == 0)
            {
                result.addError(ApkVerifier.Issue.V2_SIG_NO_SIGNATURES);
                return;
            }

            // Verify signatures over signed-data block using the public key
            List<ApkSigningBlockUtils.SupportedSignature> signaturesToVerify = null;
            try
            {
                signaturesToVerify =
                    ApkSigningBlockUtils.getSignaturesToVerify(
                        supportedSignatures, minSdkVersion, maxSdkVersion);
            }
            catch (ApkSigningBlockUtils.NoSupportedSignaturesException e)
            {
                result.addError(ApkVerifier.Issue.V2_SIG_NO_SUPPORTED_SIGNATURES, e);
                return;
            }

            foreach (ApkSigningBlockUtils.SupportedSignature signature in signaturesToVerify)
            {
                SignatureAlgorithm signatureAlgorithm = signature.algorithm;
                String jcaSignatureAlgorithm =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams().Item1;
                AlgorithmParameterSpec jcaSignatureAlgorithmParams =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams().Item2;
                String keyAlgorithm = signatureAlgorithm.getJcaKeyAlgorithm();
                PublicKey publicKey;
                try
                {
                    publicKey = PublicKey.FromEncoded(keyAlgorithm, publicKeyBytes);
                }
                catch (Exception e)
                {
                    result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_PUBLIC_KEY, e);
                    return;
                }

                try
                {
                    Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                    sig.initVerify(publicKey);
                    if (jcaSignatureAlgorithmParams != null)
                    {
                        sig.setParameter(jcaSignatureAlgorithmParams);
                    }

                    signedData.position(0);
                    sig.update(signedData);
                    byte[] sigBytes = signature.signature;
                    if (!sig.verify(sigBytes))
                    {
                        result.addError(ApkVerifier.Issue.V2_SIG_DID_NOT_VERIFY, signatureAlgorithm);
                        return;
                    }

                    result.verifiedSignatures.Add(signatureAlgorithm, sigBytes);
                    contentDigestsToVerify.Add(signatureAlgorithm.getContentDigestAlgorithm());
                }
                catch (CryptographicException e)
                {
                    result.addError(ApkVerifier.Issue.V2_SIG_VERIFY_EXCEPTION, signatureAlgorithm, e);
                    return;
                }
            }

            // At least one signature over signedData has verified. We can now parse signed-data.
            signedData.position(0);
            ByteBuffer digests = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            ByteBuffer certificates = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            ByteBuffer additionalAttributes = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);

            // Parse the certificates block
            int certificateIndex = -1;
            while (certificates.hasRemaining())
            {
                certificateIndex++;
                byte[] encodedCert = ApkSigningBlockUtils.readLengthPrefixedByteArray(certificates);
                X509Certificate certificate;
                try
                {
                    certificate = X509CertificateUtils.generateCertificate(encodedCert);
                }
                catch (CryptographicException e)
                {
                    result.addError(
                        ApkVerifier.Issue.V2_SIG_MALFORMED_CERTIFICATE,
                        certificateIndex,
                        certificateIndex + 1,
                        e);
                    return;
                }

                // Wrap the cert so that the result's getEncoded returns exactly the original encoded
                // form. Without this, getEncoded may return a different form from what was stored in
                // the signature. This is because some X509Certificate(Factory) implementations
                // re-encode certificates.
                certificate = new GuaranteedEncodedFormX509Certificate(certificate, encodedCert);
                result.certs.Add(certificate);
            }

            if (result.certs.Count == 0)
            {
                result.addError(ApkVerifier.Issue.V2_SIG_NO_CERTIFICATES);
                return;
            }

            X509Certificate mainCertificate = result.certs[0];
            byte[] certificatePublicKeyBytes;
            try
            {
                certificatePublicKeyBytes = ApkSigningBlockUtils.encodePublicKey(
                    mainCertificate.getPublicKey());
            }
            catch (CryptographicException e)
            {
                certificatePublicKeyBytes = mainCertificate.getPublicKey().getEncoded();
            }

            if (!publicKeyBytes.SequenceEqual(certificatePublicKeyBytes))
            {
                result.addError(
                    ApkVerifier.Issue.V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,
                    ApkSigningBlockUtils.toHex(certificatePublicKeyBytes),
                    ApkSigningBlockUtils.toHex(publicKeyBytes));
                return;
            }

            // Parse the digests block
            int digestCount = 0;
            while (digests.hasRemaining())
            {
                digestCount++;
                try
                {
                    ByteBuffer digest = ApkSigningBlockUtils.getLengthPrefixedSlice(digests);
                    int sigAlgorithmId = digest.getInt();
                    byte[] digestBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(digest);
                    result.contentDigests.Add(
                        new ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(
                            sigAlgorithmId, digestBytes));
                }
                catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
                {
                    result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_DIGEST, digestCount);
                    return;
                }
            }

            List<int> sigAlgsFromSignaturesRecord = new List<int>(result.signatures.Count);
            foreach (ApkSigningBlockUtils.Result.SignerInfo.Signature signature in result.signatures)
            {
                sigAlgsFromSignaturesRecord.Add(signature.getAlgorithmId());
            }

            List<int> sigAlgsFromDigestsRecord = new List<int>(result.contentDigests.Count);
            foreach (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest digest in result.contentDigests)
            {
                sigAlgsFromDigestsRecord.Add(digest.getSignatureAlgorithmId());
            }

            if (!sigAlgsFromSignaturesRecord.SequenceEqual(sigAlgsFromDigestsRecord))
            {
                result.addError(
                    ApkVerifier.Issue.V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS,
                    sigAlgsFromSignaturesRecord,
                    sigAlgsFromDigestsRecord);
                return;
            }

            // Parse the additional attributes block.
            int additionalAttributeCount = 0;
            ISet<int> supportedExpectedApkSigSchemeIds = new HashSet<int>(1);
            while (additionalAttributes.hasRemaining())
            {
                additionalAttributeCount++;
                try
                {
                    ByteBuffer attribute =
                        ApkSigningBlockUtils.getLengthPrefixedSlice(additionalAttributes);
                    int id = attribute.getInt();
                    byte[] value = ByteBufferUtils.toByteArray(attribute);
                    result.additionalAttributes.Add(
                        new ApkSigningBlockUtils.Result.SignerInfo.AdditionalAttribute(id, value));
                    if (id == V2SchemeConstants.STRIPPING_PROTECTION_ATTR_ID)
                    {
                        // stripping protection added when signing with a newer scheme
                        int foundId = ByteBuffer.wrap(value).order(
                            ByteOrder.LITTLE_ENDIAN).getInt();
                        if (supportedApkSigSchemeNames.ContainsKey(foundId))
                        {
                            supportedExpectedApkSigSchemeIds.Add(foundId);
                        }
                        else
                        {
                            result.addWarning(
                                ApkVerifier.Issue.V2_SIG_UNKNOWN_APK_SIG_SCHEME_ID, result.index, foundId);
                        }
                    }
                    else
                    {
                        result.addWarning(ApkVerifier.Issue.V2_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE, id);
                    }
                }
                catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
                {
                    result.addError(
                        ApkVerifier.Issue.V2_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE, additionalAttributeCount);
                    return;
                }
            }

            // make sure that all known IDs indicated in stripping protection have already verified
            foreach (int id in supportedExpectedApkSigSchemeIds)
            {
                if (!foundApkSigSchemeIds.Contains(id))
                {
                    String apkSigSchemeName = supportedApkSigSchemeNames[id];
                    result.addError(
                        ApkVerifier.Issue.V2_SIG_MISSING_APK_SIG_REFERENCED,
                        result.index,
                        apkSigSchemeName);
                }
            }
        }
    }
}