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
using System.Security.Cryptography.X509Certificates;
using static SigningServer.Android.ApkSig.Internal.Apk.ApkSigningBlockUtils;

namespace SigningServer.Android.ApkSig.Internal.Apk.Stamp
{
    /**
     * SourceStamp signer.
     *
     * <p>SourceStamp improves traceability of apps with respect to unauthorized distribution.
     *
     * <p>The stamp is part of the APK that is protected by the signing block.
     *
     * <p>The APK contents hash is signed using the stamp key, and is saved as part of the signing
     * block.
     *
     * <p>V2 of the source stamp allows signing the digests of more than one signature schemes.
     */
    public abstract class V2SourceStampSigner
    {
        public static readonly int V2_SOURCE_STAMP_BLOCK_ID =
            SourceStampConstants.V2_SOURCE_STAMP_BLOCK_ID;

        /** Hidden constructor to prevent instantiation. */
        private V2SourceStampSigner()
        {
        }

        public static Tuple<byte[], int> generateSourceStampBlock(
            ApkSigningBlockUtils.SignerConfig sourceStampSignerConfig,
            Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> signatureSchemeDigestInfos)
        {
            if (sourceStampSignerConfig.certificates.Count == 0)
            {
                throw new CryptographicException("No certificates configured for signer");
            }

            // Extract the digests for signature schemes.
            List<Tuple<int, byte[]>> signatureSchemeDigests = new List<Tuple<int, byte[]>>();
            getSignedDigestsFor(
                VERSION_APK_SIGNATURE_SCHEME_V3,
                signatureSchemeDigestInfos,
                sourceStampSignerConfig,
                signatureSchemeDigests);
            getSignedDigestsFor(
                VERSION_APK_SIGNATURE_SCHEME_V2,
                signatureSchemeDigestInfos,
                sourceStampSignerConfig,
                signatureSchemeDigests);
            getSignedDigestsFor(
                VERSION_JAR_SIGNATURE_SCHEME,
                signatureSchemeDigestInfos,
                sourceStampSignerConfig,
                signatureSchemeDigests);

            signatureSchemeDigests.Sort((a, b) => a.Item1.CompareTo(b.Item1));

            SourceStampBlock sourceStampBlock = new SourceStampBlock();

            try
            {
                // TODO: Check encoding
                sourceStampBlock.stampCertificate =
                    sourceStampSignerConfig.certificates[0].Export(X509ContentType.Cert);
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException(
                    "Retrieving the encoded form of the stamp certificate failed", e);
            }

            sourceStampBlock.signedDigests = signatureSchemeDigests;

            sourceStampBlock.stampAttributes = encodeStampAttributes(
                generateStampAttributes(sourceStampSignerConfig.mSigningCertificateLineage));
            sourceStampBlock.signedStampAttributes =
                ApkSigningBlockUtils.generateSignaturesOverData(sourceStampSignerConfig,
                    sourceStampBlock.stampAttributes);

            // FORMAT:
            // * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded)
            // * length-prefixed sequence of length-prefixed signed signature scheme digests:
            //   * uint32: signature scheme id
            //   * length-prefixed bytes: signed digests for the respective signature scheme
            // * length-prefixed bytes: encoded stamp attributes
            // * length-prefixed sequence of length-prefixed signed stamp attributes:
            //   * uint32: signature algorithm id
            //   * length-prefixed bytes: signed stamp attributes for the respective signature algorithm
            byte[] sourceStampSignerBlock =
                encodeAsSequenceOfLengthPrefixedElements(
                    new byte[][]
                    {
                        sourceStampBlock.stampCertificate,
                        encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                            sourceStampBlock.signedDigests),
                        sourceStampBlock.stampAttributes,
                        encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                            sourceStampBlock.signedStampAttributes),
                    });

            // FORMAT:
            // * length-prefixed stamp block.
            return Tuple.Create(encodeAsLengthPrefixedElement(sourceStampSignerBlock),
                SourceStampConstants.V2_SOURCE_STAMP_BLOCK_ID);
        }

        private static void getSignedDigestsFor(
            int signatureSchemeVersion,
            Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> signatureSchemeDigestInfos,
            ApkSigningBlockUtils.SignerConfig sourceStampSignerConfig,
            List<Tuple<int, byte[]>> signatureSchemeDigests)
        {
            if (!signatureSchemeDigestInfos.ContainsKey(signatureSchemeVersion))
            {
                return;
            }

            Dictionary<ContentDigestAlgorithm, byte[]> digestInfo =
                signatureSchemeDigestInfos[signatureSchemeVersion];
            List<Tuple<int, byte[]>> digests = new List<Tuple<int, byte[]>>();
            foreach (var digest in digestInfo)
            {
                digests.Add(Tuple.Create(digest.Key.getId(), digest.Value));
            }

            digests.Sort((a, b) => a.Item1.CompareTo(b.Item2));

            // FORMAT:
            // * length-prefixed sequence of length-prefixed digests:
            //   * uint32: digest algorithm id
            //   * length-prefixed bytes: digest of the respective digest algorithm
            byte[] digestBytes =
                encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(digests);

            // FORMAT:
            // * length-prefixed sequence of length-prefixed signed digests:
            //   * uint32: signature algorithm id
            //   * length-prefixed bytes: signed digest for the respective signature algorithm
            List<Tuple<int, byte[]>> signedDigest =
                ApkSigningBlockUtils.generateSignaturesOverData(
                    sourceStampSignerConfig, digestBytes);

            // FORMAT:
            // * length-prefixed sequence of length-prefixed signed signature scheme digests:
            //   * uint32: signature scheme id
            //   * length-prefixed bytes: signed digests for the respective signature scheme
            signatureSchemeDigests.Add(
                Tuple.Create(
                    signatureSchemeVersion,
                    encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                        signedDigest)));
        }

        private static byte[] encodeStampAttributes(Dictionary<int, byte[]> stampAttributes)
        {
            int payloadSize = 0;
            foreach (byte[] attributeValue in stampAttributes.Values)
            {
                // Pair size + Attribute ID + Attribute value
                payloadSize += 4 + 4 + attributeValue.Length;
            }

            // FORMAT (little endian):
            // * length-prefixed bytes: pair
            //   * uint32: ID
            //   * bytes: value
            ByteBuffer result = ByteBuffer.allocate(4 + payloadSize);
            result.order(ByteOrder.LITTLE_ENDIAN);
            result.putInt(payloadSize);
            foreach (var stampAttribute in stampAttributes)
            {
                // Pair size
                result.putInt(4 + stampAttribute.Value.Length);
                result.putInt(stampAttribute.Key);
                result.put(stampAttribute.Value);
            }

            return result.array();
        }

        private static Dictionary<int, byte[]> generateStampAttributes(SigningCertificateLineage lineage)
        {
            Dictionary<int, byte[]> stampAttributes = new Dictionary<int, byte[]>();
            if (lineage != null)
            {
                stampAttributes.Add(SourceStampConstants.PROOF_OF_ROTATION_ATTR_ID,
                    lineage.encodeSigningCertificateLineage());
            }

            return stampAttributes;
        }

        private class SourceStampBlock
        {
            public byte[] stampCertificate;

            public List<Tuple<int, byte[]>> signedDigests;

            // Optional stamp attributes that are not required for verification.
            public byte[] stampAttributes;
            public List<Tuple<int, byte[]>> signedStampAttributes;
        }
    }
}