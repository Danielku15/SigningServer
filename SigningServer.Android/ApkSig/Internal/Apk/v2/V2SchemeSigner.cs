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
using System.Security.Cryptography;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig.Internal.Apk.v2
{
    /**
     * APK Signature Scheme v2 signer.
     *
     * <p>APK Signature Scheme v2 is a whole-file signature scheme which aims to protect every single
     * bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
     * uncompressed contents of ZIP entries.
     *
     * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2</a>
     */
    public static class V2SchemeSigner
    {
        /*
         * The two main goals of APK Signature Scheme v2 are:
         * 1. Detect any unauthorized modifications to the APK. This is achieved by making the signature
         *    cover every byte of the APK being signed.
         * 2. Enable much faster signature and integrity verification. This is achieved by requiring
         *    only a minimal amount of APK parsing before the signature is verified, thus completely
         *    bypassing ZIP entry decompression and by making integrity verification parallelizable by
         *    employing a hash tree.
         *
         * The generated signature block is wrapped into an APK Signing Block and inserted into the
         * original APK immediately before the start of ZIP Central Directory. This is to ensure that
         * JAR and ZIP parsers continue to work on the signed APK. The APK Signing Block is designed for
         * extensibility. For example, a future signature scheme could insert its signatures there as
         * well. The contract of the APK Signing Block is that all contents outside of the block must be
         * protected by signatures inside the block.
         */

        public static readonly int APK_SIGNATURE_SCHEME_V2_BLOCK_ID =
            V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID;

        /**
         * Gets the APK Signature Scheme v2 signature algorithms to be used for signing an APK using the
         * provided key.
         *
         * @param minSdkVersion minimum API Level of the platform on which the APK may be installed (see
         *     AndroidManifest.xml minSdkVersion attribute).
         * @throws InvalidKeyException if the provided key is not suitable for signing APKs using APK
         *     Signature Scheme v2
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
                    // Keys longer than 3072 bit need to be paired with a stronger digest to avoid the
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
                    // Keys longer than 256 bit need to be paired with a stronger digest to avoid the
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
            generateApkSignatureSchemeV2Block(RunnablesExecutor executor,
                DataSource beforeCentralDir,
                DataSource centralDir,
                DataSource eocd,
                List<ApkSigningBlockUtils.SignerConfig> signerConfigs,
                bool v3SigningEnabled)

        {
            return generateApkSignatureSchemeV2Block(executor, beforeCentralDir, centralDir, eocd,
                signerConfigs, v3SigningEnabled, null);
        }

        public static ApkSigningBlockUtils.SigningSchemeBlockAndDigests
            generateApkSignatureSchemeV2Block(
                RunnablesExecutor executor,
                DataSource beforeCentralDir,
                DataSource centralDir,
                DataSource eocd,
                List<ApkSigningBlockUtils.SignerConfig> signerConfigs,
                bool v3SigningEnabled,
                List<byte[]> preservedV2SignerBlocks)

        {
            Tuple<List<ApkSigningBlockUtils.SignerConfig>, Dictionary<ContentDigestAlgorithm, byte[]>> digestInfo =
                ApkSigningBlockUtils.computeContentDigests(
                    executor, beforeCentralDir, centralDir, eocd, signerConfigs);
            return new ApkSigningBlockUtils.SigningSchemeBlockAndDigests(
                generateApkSignatureSchemeV2Block(
                    digestInfo.Item1, digestInfo.Item2, v3SigningEnabled,
                    preservedV2SignerBlocks),
                digestInfo.Item2);
        }

        private static Tuple<byte[], int> generateApkSignatureSchemeV2Block(
            List<ApkSigningBlockUtils.SignerConfig> signerConfigs,
            Dictionary<ContentDigestAlgorithm, byte[]> contentDigests,
            bool v3SigningEnabled,
            List<byte[]> preservedV2SignerBlocks)

        {
            // FORMAT:
            // * length-prefixed sequence of length-prefixed signer blocks.

            List<byte[]> signerBlocks = new List<byte[]>(signerConfigs.Count);
            if (preservedV2SignerBlocks != null && preservedV2SignerBlocks.Count > 0)
            {
                signerBlocks.AddRange(preservedV2SignerBlocks);
            }

            int signerNumber = 0;
            foreach (var signerConfig in signerConfigs)
            {
                signerNumber++;
                byte[] signerBlock;
                try
                {
                    signerBlock = generateSignerBlock(signerConfig, contentDigests, v3SigningEnabled);
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
                V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID);
        }

        private static byte[] generateSignerBlock(
            ApkSigningBlockUtils.SignerConfig signerConfig,
            Dictionary<ContentDigestAlgorithm, byte[]> contentDigests,
            bool v3SigningEnabled)

        {
            if (signerConfig.certificates.Count == 0)
            {
                throw new CryptographicException("No certificates configured for signer");
            }

            PublicKey publicKey = signerConfig.certificates[0].getPublicKey();

            byte[] encodedPublicKey = ApkSigningBlockUtils.encodePublicKey(publicKey);

            V2SignatureSchemeBlock.SignedData signedData = new V2SignatureSchemeBlock.SignedData();
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
            signedData.additionalAttributes = generateAdditionalAttributes(v3SigningEnabled);

            V2SignatureSchemeBlock.Signer signer = new V2SignatureSchemeBlock.Signer();
            // FORMAT:
            // * length-prefixed sequence of length-prefixed digests:
            //   * uint32: signature algorithm ID
            //   * length-prefixed bytes: digest of contents
            // * length-prefixed sequence of certificates:
            //   * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
            // * length-prefixed sequence of length-prefixed additional attributes:
            //   * uint32: ID
            //   * (length - 4) bytes: value

            signer.signedData =
                ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(
                    new byte[][]
                    {
                        ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                            signedData.digests),
                        ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(signedData.certificates),
                        signedData.additionalAttributes,
                        new byte[0],
                    });
            signer.publicKey = encodedPublicKey;
            signer.signatures = new List<Tuple<int, byte[]>>();
            signer.signatures =
                ApkSigningBlockUtils.generateSignaturesOverData(signerConfig, signer.signedData);

            // FORMAT:
            // * length-prefixed signed data
            // * length-prefixed sequence of length-prefixed signatures:
            //   * uint32: signature algorithm ID
            //   * length-prefixed bytes: signature of signed data
            // * length-prefixed bytes: public key (X.509 SubjectPublicKeyInfo, ASN.1 DER encoded)
            return ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(
                new byte[][]
                {
                    signer.signedData,
                    ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                        signer.signatures),
                    signer.publicKey,
                });
        }

        private static byte[] generateAdditionalAttributes(bool v3SigningEnabled)
        {
            if (v3SigningEnabled)
            {
                // FORMAT (little endian):
                // * length-prefixed bytes: attribute pair
                //   * uint32: ID - STRIPPING_PROTECTION_ATTR_ID in this case
                //   * uint32: value - 3 (v3 signature scheme id) in this case
                int payloadSize = 4 + 4 + 4;
                ByteBuffer result = ByteBuffer.allocate(payloadSize);
                result.order(ByteOrder.LITTLE_ENDIAN);
                result.putInt(payloadSize - 4);
                result.putInt(V2SchemeConstants.STRIPPING_PROTECTION_ATTR_ID);
                result.putInt(ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
                return result.array();
            }
            else
            {
                return new byte[0];
            }
        }

        private class V2SignatureSchemeBlock
        {
            public class Signer
            {
                public byte[] signedData;
                public List<Tuple<int, byte[]>> signatures;
                public byte[] publicKey;
            }

            public class SignedData
            {
                public List<Tuple<int, byte[]>> digests;
                public List<byte[]> certificates;
                public byte[] additionalAttributes;
            }
        }
    }
}