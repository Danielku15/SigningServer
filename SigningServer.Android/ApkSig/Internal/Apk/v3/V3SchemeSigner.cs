/*
 * Copyright (C) 2018 The Android Open Source Project
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
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig.Internal.Apk.v3
{
    /**
     * APK Signature Scheme v3 signer.
     *
     * <p>APK Signature Scheme v3 builds upon APK Signature Scheme v3, and maintains all of the APK
     * Signature Scheme v2 goals.
     *
     * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2</a>
     *     <p>The main contribution of APK Signature Scheme v3 is the introduction of the {@link
     *     SigningCertificateLineage}, which enables an APK to change its signing certificate as long as
     *     it can prove the new siging certificate was signed by the old.
     */
    public static class V3SchemeSigner
    {
        public static readonly int APK_SIGNATURE_SCHEME_V3_BLOCK_ID =
            V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID;

        public static readonly int PROOF_OF_ROTATION_ATTR_ID = V3SchemeConstants.PROOF_OF_ROTATION_ATTR_ID;

        /**
     * Gets the APK Signature Scheme v3 signature algorithms to be used for signing an APK using the
     * provided key.
     *
     * @param minSdkVersion minimum API Level of the platform on which the APK may be installed (see
     *     AndroidManifest.xml minSdkVersion attribute).
     * @throws InvalidKeyException if the provided key is not suitable for signing APKs using APK
     *     Signature Scheme v3
     */
        public static List<SignatureAlgorithm> getSuggestedSignatureAlgorithms(PublicKey signingKey,
            int minSdkVersion, bool verityEnabled, bool deterministicDsaSigning)

        {
            String keyAlgorithm = signingKey.getAlgorithm();
            if ("RSA".Equals(keyAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                // Use RSASSA-PKCS1-v1_5 signature scheme instead of RSASSA-PSS to guarantee
                // deterministic signatures which make life easier for OTA updates (fewer files
                // changed when deterministic signature schemes are used).

                // Pick a digest which is no weaker than the key.
                int modulusLengthBits = ((RSAKey)signingKey).getModulus().bitLength();
                if (modulusLengthBits <= 3072)
                {
                    // 3072-bit RSA is roughly 128-bit strong, meaning SHA-256 is a good fit.
                    List<SignatureAlgorithm> algorithms = new List<SignatureAlgorithm>();
                    algorithms.Add(SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256);
                    if (verityEnabled)
                    {
                        algorithms.Add(SignatureAlgorithm.VERITY_RSA_PKCS1_V1_5_WITH_SHA256);
                    }

                    return algorithms;
                }
                else
                {
                    // Keys longer than 3072 bit need to be Tupleed with a stronger digest to avoid the
                    // digest being the weak link. SHA-512 is the next strongest supported digest.
                    return new List<SignatureAlgorithm>
                    {
                        SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA512
                    };
                }
            }

            else if ("DSA".Equals(keyAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                // DSA is supported only with SHA-256.
                List<SignatureAlgorithm> algorithms = new List<SignatureAlgorithm>();
                algorithms.Add(
                    deterministicDsaSigning
                        ? SignatureAlgorithm.DETDSA_WITH_SHA256
                        : SignatureAlgorithm.DSA_WITH_SHA256);
                if (verityEnabled)
                {
                    algorithms.Add(SignatureAlgorithm.VERITY_DSA_WITH_SHA256);
                }

                return algorithms;
            }
            else if ("EC".Equals(keyAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                // Pick a digest which is no weaker than the key.
                int keySizeBits = ((ECKey)signingKey).getParams().getOrder().bitLength();
                if (keySizeBits <= 256)
                {
                    // 256-bit Elliptic Curve is roughly 128-bit strong, meaning SHA-256 is a good fit.
                    List<SignatureAlgorithm> algorithms = new List<SignatureAlgorithm>();
                    algorithms.Add(SignatureAlgorithm.ECDSA_WITH_SHA256);
                    if (verityEnabled)
                    {
                        algorithms.Add(SignatureAlgorithm.VERITY_ECDSA_WITH_SHA256);
                    }

                    return algorithms;
                }
                else
                {
                    // Keys longer than 256 bit need to be Tupleed with a stronger digest to avoid the
                    // digest being the weak link. SHA-512 is the next strongest supported digest.
                    return new List<SignatureAlgorithm>
                    {
                        SignatureAlgorithm.ECDSA_WITH_SHA512
                    };
                }
            }
            else
            {
                throw new CryptographicException("Unsupported key algorithm: " + keyAlgorithm);
            }
        }

        public static ApkSigningBlockUtils.SigningSchemeBlockAndDigests
            generateApkSignatureSchemeV3Block(
                RunnablesExecutor executor,
                DataSource beforeCentralDir,
                DataSource centralDir,
                DataSource eocd,
                List<ApkSigningBlockUtils.SignerConfig> signerConfigs)

        {
            Tuple<List<ApkSigningBlockUtils.SignerConfig>, Dictionary<ContentDigestAlgorithm, byte[]>> digestInfo =
                ApkSigningBlockUtils.computeContentDigests(
                    executor, beforeCentralDir, centralDir, eocd, signerConfigs);
            return new ApkSigningBlockUtils.SigningSchemeBlockAndDigests(
                generateApkSignatureSchemeV3Block(digestInfo.Item1, digestInfo.Item2),
                digestInfo.Item2);
        }

        public static byte[] generateV3SignerAttribute(
            SigningCertificateLineage signingCertificateLineage)
        {
            // FORMAT (little endian):
            // * length-prefixed bytes: attribute Tuple
            //   * uint32: ID
            //   * bytes: value - encoded V3 SigningCertificateLineage
            byte[] encodedLineage = signingCertificateLineage.encodeSigningCertificateLineage();
            int payloadSize = 4 + 4 + encodedLineage.Length;
            ByteBuffer result = ByteBuffer.allocate(payloadSize);
            result.order(ByteOrder.LITTLE_ENDIAN);
            result.putInt(4 + encodedLineage.Length);
            result.putInt(V3SchemeConstants.PROOF_OF_ROTATION_ATTR_ID);
            result.put(encodedLineage);
            return result.array();
        }

        private static Tuple<byte[], int> generateApkSignatureSchemeV3Block(
            List<ApkSigningBlockUtils.SignerConfig> signerConfigs,
            Dictionary<ContentDigestAlgorithm, byte[]> contentDigests)

        {
            // FORMAT:
            // * length-prefixed sequence of length-prefixed signer blocks.
            List<byte[]> signerBlocks = new List<byte[]>(signerConfigs.Count);
            int signerNumber = 0;
            foreach (ApkSigningBlockUtils.SignerConfig signerConfig in signerConfigs)
            {
                signerNumber++;
                byte[] signerBlock;
                try
                {
                    signerBlock = generateSignerBlock(signerConfig, contentDigests);
                }
                catch (CryptographicException e)
                {
                    throw new CryptographicException("Signer #" + signerNumber + " failed", e);
                }

                signerBlocks.Add(signerBlock);
            }

            return Tuple.Create(
                ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(
                    new byte[][]
                    {
                        ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(signerBlocks),
                    }),
                V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID);
        }

        private static byte[] generateSignerBlock(
            ApkSigningBlockUtils.SignerConfig signerConfig, Dictionary<ContentDigestAlgorithm, byte[]> contentDigests)

        {
            if (signerConfig.certificates.Count == 0)
            {
                throw new CryptographicException("No certificates configured for signer");
            }

            PublicKey publicKey = signerConfig.certificates[0].getPublicKey();

            byte[] encodedPublicKey = ApkSigningBlockUtils.encodePublicKey(publicKey);

            V3SignatureSchemeBlock.SignedData signedData = new V3SignatureSchemeBlock.SignedData();
            try
            {
                signedData.certificates = ApkSigningBlockUtils.encodeCertificates(signerConfig.certificates);
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException("Failed to encode certificates", e);
            }

            List<Tuple<int, byte[]>> digests =
                new List<Tuple<int, byte[]>>(signerConfig.signatureAlgorithms.Count);
            foreach (SignatureAlgorithm signatureAlgorithm in signerConfig.signatureAlgorithms)
            {
                ContentDigestAlgorithm contentDigestAlgorithm =
                    signatureAlgorithm.getContentDigestAlgorithm();
                contentDigests.TryGetValue(contentDigestAlgorithm, out var contentDigest);
                if (contentDigest == null)
                {
                    throw new ApplicationException(
                        contentDigestAlgorithm
                        + " content digest for "
                        + signatureAlgorithm
                        + " not computed");
                }

                digests.Add(Tuple.Create(signatureAlgorithm.getId(), contentDigest));
            }

            signedData.digests = digests;
            signedData.minSdkVersion = signerConfig.minSdkVersion;
            signedData.maxSdkVersion = signerConfig.maxSdkVersion;
            signedData.additionalAttributes = generateAdditionalAttributes(signerConfig);

            V3SignatureSchemeBlock.Signer signer = new V3SignatureSchemeBlock.Signer();

            signer.signedData = encodeSignedData(signedData);

            signer.minSdkVersion = signerConfig.minSdkVersion;
            signer.maxSdkVersion = signerConfig.maxSdkVersion;
            signer.publicKey = encodedPublicKey;
            signer.signatures =
                ApkSigningBlockUtils.generateSignaturesOverData(signerConfig, signer.signedData);

            return encodeSigner(signer);
        }

        private static byte[] encodeSigner(V3SignatureSchemeBlock.Signer signer)
        {
            byte[] signedData = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(signer.signedData);
            byte[] signatures =
                ApkSigningBlockUtils.encodeAsLengthPrefixedElement(
                    ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                        signer.signatures));
            byte[] publicKey = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(signer.publicKey);

            // FORMAT:
            // * length-prefixed signed data
            // * uint32: minSdkVersion
            // * uint32: maxSdkVersion
            // * length-prefixed sequence of length-prefixed signatures:
            //   * uint32: signature algorithm ID
            //   * length-prefixed bytes: signature of signed data
            // * length-prefixed bytes: public key (X.509 SubjectPublicKeyInfo, ASN.1 DER encoded)
            int payloadSize = signedData.Length + 4 + 4 + signatures.Length + publicKey.Length;

            ByteBuffer result = ByteBuffer.allocate(payloadSize);
            result.order(ByteOrder.LITTLE_ENDIAN);
            result.put(signedData);
            result.putInt(signer.minSdkVersion);
            result.putInt(signer.maxSdkVersion);
            result.put(signatures);
            result.put(publicKey);

            return result.array();
        }

        private static byte[] encodeSignedData(V3SignatureSchemeBlock.SignedData signedData)
        {
            byte[] digests =
                ApkSigningBlockUtils.encodeAsLengthPrefixedElement(
                    ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                        signedData.digests));
            byte[] certs =
                ApkSigningBlockUtils.encodeAsLengthPrefixedElement(
                    ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(signedData.certificates));
            byte[] attributes = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(signedData.additionalAttributes);

            // FORMAT:
            // * length-prefixed sequence of length-prefixed digests:
            //   * uint32: signature algorithm ID
            //   * length-prefixed bytes: digest of contents
            // * length-prefixed sequence of certificates:
            //   * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
            // * uint-32: minSdkVersion
            // * uint-32: maxSdkVersion
            // * length-prefixed sequence of length-prefixed additional attributes:
            //   * uint32: ID
            //   * (length - 4) bytes: value
            //   * uint32: Proof-of-rotation ID: 0x3ba06f8c
            //   * length-prefixed roof-of-rotation structure
            int payloadSize = digests.Length + certs.Length + 4 + 4 + attributes.Length;

            ByteBuffer result = ByteBuffer.allocate(payloadSize);
            result.order(ByteOrder.LITTLE_ENDIAN);
            result.put(digests);
            result.put(certs);
            result.putInt(signedData.minSdkVersion);
            result.putInt(signedData.maxSdkVersion);
            result.put(attributes);

            return result.array();
        }

        private static byte[] generateAdditionalAttributes(ApkSigningBlockUtils.SignerConfig signerConfig)
        {
            if (signerConfig.mSigningCertificateLineage == null)
            {
                return new byte[0];
            }

            return generateV3SignerAttribute(signerConfig.mSigningCertificateLineage);
        }

        private class V3SignatureSchemeBlock
        {
            public class Signer
            {
                public byte[] signedData;
                public int minSdkVersion;
                public int maxSdkVersion;
                public List<Tuple<int, byte[]>> signatures;
                public byte[] publicKey;
            }

            public class SignedData
            {
                public List<Tuple<int, byte[]>> digests;
                public List<byte[]> certificates;
                public int minSdkVersion;
                public int maxSdkVersion;
                public byte[] additionalAttributes;
            }
        }
    }
}