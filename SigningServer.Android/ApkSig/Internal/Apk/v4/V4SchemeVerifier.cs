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
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig.Internal.Apk.v4
{
    /**
     * APK Signature Scheme V4 verifier.
     * <p>
     * Verifies the serialized V4Signature file against an APK.
     */
    public static class V4SchemeVerifier
    {
        /**
         * <p>
         * The main goals of the verifier are: 1) parse V4Signature file fields 2) verifies the PKCS7
         * signature block against the raw root hash bytes in the proto field 3) verifies that the raw
         * root hash matches with the actual hash tree root of the give APK 4) if the file contains a
         * verity tree, verifies that it matches with the actual verity tree computed from the given
         * APK.
         * </p>
         */
        public static ApkSigningBlockUtils.Result verify(DataSource apk, FileInfo v4SignatureFile)
        {
            V4Signature signature;
            byte[] tree;
            using(var input = v4SignatureFile.OpenRead()) {
                signature = V4Signature.readFrom(input);
                tree = V4Signature.readBytes(input);
            }

            ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V4);

            if (signature == null)
            {
                result.addError(ApkVerifier.Issue.V4_SIG_NO_SIGNATURES,
                    "Signature file does not contain a v4 signature.");
                return result;
            }

            if (signature.version != V4Signature.CURRENT_VERSION)
            {
                result.addWarning(ApkVerifier.Issue.V4_SIG_VERSION_NOT_CURRENT, signature.version,
                    V4Signature.CURRENT_VERSION);
            }

            V4Signature.HashingInfo hashingInfo = V4Signature.HashingInfo.fromByteArray(
                signature.hashingInfo);
            V4Signature.SigningInfo signingInfo = V4Signature.SigningInfo.fromByteArray(
                signature.signingInfo);

            byte[] signedData = V4Signature.getSignedData(apk.size(), hashingInfo, signingInfo);

            // First, verify the signature over signedData.
            ApkSigningBlockUtils.Result.SignerInfo signerInfo = parseAndVerifySignatureBlock(
                signingInfo, signedData);
            result.signers.Add(signerInfo);
            if (result.containsErrors())
            {
                return result;
            }

            // Second, check if the root hash and the tree are correct.
            verifyRootHashAndTree(apk, signerInfo, hashingInfo.rawRootHash, tree);
            if (!result.containsErrors())
            {
                result.verified = true;
            }

            return result;
        }

        /**
     * Parses the provided signature block and populates the {@code result}.
     * <p>
     * This verifies {@signingInfo} over {@code signedData}, as well as parsing the certificate
     * contained in the signature block. This method adds one or more errors to the {@code result}.
     */
        private static ApkSigningBlockUtils.Result.SignerInfo parseAndVerifySignatureBlock(
            V4Signature.SigningInfo signingInfo,
            byte[] signedData)
        {
            ApkSigningBlockUtils.Result.SignerInfo result =
                new ApkSigningBlockUtils.Result.SignerInfo();
            result.index = 0;

            int sigAlgorithmId = signingInfo.signatureAlgorithmId;
            byte[] sigBytes = signingInfo.signature;
            result.signatures.Add(
                new ApkSigningBlockUtils.Result.SignerInfo.Signature(sigAlgorithmId, sigBytes));

            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(sigAlgorithmId);
            if (signatureAlgorithm == null)
            {
                result.addError(ApkVerifier.Issue.V4_SIG_UNKNOWN_SIG_ALGORITHM, sigAlgorithmId);
                return result;
            }

            String jcaSignatureAlgorithm =
                signatureAlgorithm.getJcaSignatureAlgorithmAndParams().Item1;

            AlgorithmParameterSpec jcaSignatureAlgorithmParams =
                signatureAlgorithm.getJcaSignatureAlgorithmAndParams().Item2;

            String keyAlgorithm = signatureAlgorithm.getJcaKeyAlgorithm();

            byte[] publicKeyBytes = signingInfo.publicKey;

            PublicKey publicKey;
            try
            {
                publicKey = PublicKey.FromEncoded(keyAlgorithm, publicKeyBytes);
            }
            catch
                (Exception e)
            {
                result.addError(ApkVerifier.Issue.V4_SIG_MALFORMED_PUBLIC_KEY, e);
                return result;
            }

            try
            {
                Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                sig.initVerify(publicKey);
                if (jcaSignatureAlgorithmParams != null)
                {
                    sig.setParameter(jcaSignatureAlgorithmParams);
                }

                sig.update(signedData);
                if (!sig.verify(sigBytes))
                {
                    result.addError(ApkVerifier.Issue.V4_SIG_DID_NOT_VERIFY, signatureAlgorithm);
                    return result;
                }

                result.verifiedSignatures.Add(signatureAlgorithm, sigBytes);
            }
            catch (CryptographicException e) {
                result.addError(ApkVerifier.Issue.V4_SIG_VERIFY_EXCEPTION, signatureAlgorithm, e);
                return result;
            }

            if (signingInfo.certificate == null)
            {
                result.addError(ApkVerifier.Issue.V4_SIG_NO_CERTIFICATE);
                return result;
            }

            X509Certificate certificate;
            try
            {
                // Wrap the cert so that the result's getEncoded returns exactly the original encoded
                // form. Without this, getEncoded may return a different form from what was stored in
                // the signature. This is because some X509Certificate(Factory) implementations
                // re-encode certificates.
                certificate = new GuaranteedEncodedFormX509Certificate(
                    X509CertificateUtils.generateCertificate(signingInfo.certificate),
                    signingInfo.certificate);
            }
            catch (CryptographicException e)
            {
                result.addError(ApkVerifier.Issue.V4_SIG_MALFORMED_CERTIFICATE, e);
                return result;
            }

            result.certs.Add(certificate);

            byte[] certificatePublicKeyBytes;
            try
            {
                certificatePublicKeyBytes = ApkSigningBlockUtils.encodePublicKey(
                    certificate.getPublicKey());
            }
            catch (CryptographicException e)
            {
                certificatePublicKeyBytes = certificate.getPublicKey().getEncoded();
            }

            if (!publicKeyBytes.SequenceEqual(certificatePublicKeyBytes))
            {
                result.addError(
                    ApkVerifier.Issue.V4_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,
                    ApkSigningBlockUtils.toHex(certificatePublicKeyBytes),
                    ApkSigningBlockUtils.toHex(publicKeyBytes));
                return result;
            }

            // Add apk digest from the file to the result.
            ApkSigningBlockUtils.Result.SignerInfo.ContentDigest contentDigest =
                new ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(
                    0 /* signature algorithm id doesn't matter here */, signingInfo.apkDigest);
            result.contentDigests.Add(contentDigest);

            return result;
        }

        private static void verifyRootHashAndTree(DataSource apkContent,
            ApkSigningBlockUtils.Result.SignerInfo signerInfo, byte[] expectedDigest,
            byte[] expectedTree)

        {
            ApkSigningBlockUtils.VerityTreeAndDigest actualContentDigestInfo =
                ApkSigningBlockUtils.computeChunkVerityTreeAndDigest(apkContent);

            ContentDigestAlgorithm algorithm = actualContentDigestInfo.contentDigestAlgorithm;
            byte[] actualDigest = actualContentDigestInfo.rootHash;
            byte[] actualTree = actualContentDigestInfo.tree;

            if (!expectedDigest.SequenceEqual(actualDigest))
            {
                signerInfo.addError(
                    ApkVerifier.Issue.V4_SIG_APK_ROOT_DID_NOT_VERIFY,
                    algorithm,
                    ApkSigningBlockUtils.toHex(expectedDigest),
                    ApkSigningBlockUtils.toHex(actualDigest));
                return;
            }

            // Only check verity tree if it is not empty
            if (expectedTree != null && !expectedTree.SequenceEqual(actualTree))
            {
                signerInfo.addError(
                    ApkVerifier.Issue.V4_SIG_APK_TREE_DID_NOT_VERIFY,
                    algorithm,
                    ApkSigningBlockUtils.toHex(expectedDigest),
                    ApkSigningBlockUtils.toHex(actualDigest));
                return;
            }

            signerInfo.verifiedContentDigests.Add(algorithm, actualDigest);
        }
    }
}