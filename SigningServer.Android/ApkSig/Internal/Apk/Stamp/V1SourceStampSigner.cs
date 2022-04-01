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
     * <p>V1 of the source stamp allows signing the digest of at most one signature scheme only.
     */
    public abstract class V1SourceStampSigner
    {
        public static readonly int V1_SOURCE_STAMP_BLOCK_ID =
            SourceStampConstants.V1_SOURCE_STAMP_BLOCK_ID;

        /** Hidden constructor to prevent instantiation. */
        private V1SourceStampSigner()
        {
        }

        public static Tuple<byte[], int> generateSourceStampBlock(
            ApkSigningBlockUtils.SignerConfig sourceStampSignerConfig,
            Dictionary<ContentDigestAlgorithm, byte[]> digestInfo)
        {
            if (sourceStampSignerConfig.certificates.Count == 0)
            {
                throw new CryptographicException("No certificates configured for signer");
            }

            List<Tuple<int, byte[]>> digests = new List<Tuple<int, byte[]>>();
            foreach (var digest in digestInfo)
            {
                digests.Add(Tuple.Create(digest.Key.getId(), digest.Value));
            }

            digests.Sort((a, b) => a.Item1.CompareTo(b.Item1));

            SourceStampBlock sourceStampBlock = new SourceStampBlock();

            try
            {
                sourceStampBlock.stampCertificate =
                    sourceStampSignerConfig.certificates[0].getEncoded();
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException(
                    "Retrieving the encoded form of the stamp certificate failed", e);
            }

            byte[] digestBytes =
                encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(digests);
            sourceStampBlock.signedDigests =
                ApkSigningBlockUtils.generateSignaturesOverData(
                    sourceStampSignerConfig, digestBytes);

            // FORMAT:
            // * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded)
            // * length-prefixed sequence of length-prefixed signatures:
            //   * uint32: signature algorithm ID
            //   * length-prefixed bytes: signature of signed data
            byte[] sourceStampSignerBlock =
                encodeAsSequenceOfLengthPrefixedElements(
                    new byte[][]
                    {
                        sourceStampBlock.stampCertificate,
                        encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                            sourceStampBlock.signedDigests),
                    });

            // FORMAT:
            // * length-prefixed stamp block.
            return Tuple.Create(encodeAsLengthPrefixedElement(sourceStampSignerBlock),
                SourceStampConstants.V1_SOURCE_STAMP_BLOCK_ID);
        }

        private class SourceStampBlock
        {
            public byte[] stampCertificate;
            public List<Tuple<int, byte[]>> signedDigests;
        }
    }
}