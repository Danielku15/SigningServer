/*
 * Copyright (C) 2017 The Android Open Source Project
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
using System.Security.Cryptography;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Android.ApkSig.Internal.Asn1;
using static SigningServer.Android.ApkSig.Internal.Oid.OidConstants;

namespace SigningServer.Android.ApkSig.Internal.Pkcs7
{
    /**
     * PKCS #7 {@code AlgorithmIdentifier} as specified in RFC 5652.
     */
    [Asn1Class(Type = Asn1Type.SEQUENCE)]
    public class AlgorithmIdentifier
    {
        [Asn1Field(Index = 0, Type = Asn1Type.OBJECT_IDENTIFIER)]
        public String algorithm;

        [Asn1Field(Index = 1, Type = Asn1Type.ANY, Optional = true)]
        public Asn1OpaqueObject parameters;

        public AlgorithmIdentifier()
        {
        }

        public AlgorithmIdentifier(String algorithmOid, Asn1OpaqueObject parameters)
        {
            this.algorithm = algorithmOid;
            this.parameters = parameters;
        }

        /**
         * Returns the PKCS #7 {@code DigestAlgorithm} to use when signing using the specified digest
         * algorithm.
         */
        public static AlgorithmIdentifier getSignerInfoDigestAlgorithmOid(
            DigestAlgorithm digestAlgorithm)
        {
            switch (digestAlgorithm)
            {
                case DigestAlgorithm.SHA1:
                    return new AlgorithmIdentifier(OID_DIGEST_SHA1, Asn1DerEncoder.ASN1_DER_NULL);
                case DigestAlgorithm.SHA256:
                    return new AlgorithmIdentifier(OID_DIGEST_SHA256, Asn1DerEncoder.ASN1_DER_NULL);
            }

            throw new ArgumentException("Unsupported digest algorithm: " + digestAlgorithm);
        }

        /**
         * Returns the JCA {@link Signature} algorithm and PKCS #7 {@code SignatureAlgorithm} to use
         * when signing with the specified key and digest algorithm.
         */
        public static Tuple<String, AlgorithmIdentifier> getSignerInfoSignatureAlgorithm(
            PublicKey publicKey, DigestAlgorithm digestAlgorithm, bool deterministicDsaSigning)
        {
            String keyAlgorithm = publicKey.getAlgorithm();
            String jcaDigestPrefixForSigAlg;
            switch (digestAlgorithm)
            {
                case DigestAlgorithm.SHA1:
                    jcaDigestPrefixForSigAlg = "SHA1";
                    break;
                case DigestAlgorithm.SHA256:
                    jcaDigestPrefixForSigAlg = "SHA256";
                    break;
                default:
                    throw new ArgumentException(
                        "Unexpected digest algorithm: " + digestAlgorithm);
            }

            if ("RSA".Equals(keyAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                return Tuple.Create(
                    jcaDigestPrefixForSigAlg + "withRSA",
                    new AlgorithmIdentifier(OID_SIG_RSA, Asn1DerEncoder.ASN1_DER_NULL));
            }
            else if ("DSA".Equals(keyAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                AlgorithmIdentifier sigAlgId;
                switch (digestAlgorithm)
                {
                    case DigestAlgorithm.SHA1:
                        sigAlgId =
                            new AlgorithmIdentifier(OID_SIG_DSA, Asn1DerEncoder.ASN1_DER_NULL);
                        break;
                    case DigestAlgorithm.SHA256:
                        // DSA signatures with SHA-256 in SignedData are accepted by Android API Level
                        // 21 and higher. However, there are two ways to specify their SignedData
                        // SignatureAlgorithm: dsaWithSha256 (2.16.840.1.101.3.4.3.2) and
                        // dsa (1.2.840.10040.4.1). The latter works only on API Level 22+. Thus, we use
                        // the former.
                        sigAlgId =
                            new AlgorithmIdentifier(OID_SIG_SHA256_WITH_DSA, Asn1DerEncoder.ASN1_DER_NULL);
                        break;
                    default:
                        throw new ArgumentException(
                            "Unexpected digest algorithm: " + digestAlgorithm);
                }

                String signingAlgorithmName =
                    jcaDigestPrefixForSigAlg + (deterministicDsaSigning ? "withDetDSA" : "withDSA");
                return Tuple.Create(signingAlgorithmName, sigAlgId);
            }
            else if ("EC".Equals(keyAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                return Tuple.Create(
                    jcaDigestPrefixForSigAlg + "withECDSA",
                    new AlgorithmIdentifier(OID_SIG_EC_PUBLIC_KEY, Asn1DerEncoder.ASN1_DER_NULL));
            }
            else
            {
                throw new CryptographicException("Unsupported key algorithm: " + keyAlgorithm);
            }
        }

        public static String getJcaSignatureAlgorithm(
            String digestAlgorithmOid,
            String signatureAlgorithmOid)

        {
            // First check whether the signature algorithm OID alone is sufficient
            if (OID_TO_JCA_SIGNATURE_ALG.TryGetValue(signatureAlgorithmOid, out var result))
            {
                return result;
            }

            // Signature algorithm OID alone is insufficient. Need to combine digest algorithm OID
            // with signature algorithm OID.
            String suffix;
            if (OID_SIG_RSA.Equals(signatureAlgorithmOid))
            {
                suffix = "RSA";
            }

            else if (OID_SIG_DSA.Equals(signatureAlgorithmOid))
            {
                suffix = "DSA";
            }
            else if (OID_SIG_EC_PUBLIC_KEY.Equals(signatureAlgorithmOid))
            {
                suffix = "ECDSA";
            }
            else
            {
                throw new CryptographicException(
                    "Unsupported JCA Signature algorithm"
                    + " . Digest algorithm: " + digestAlgorithmOid
                    + ", signature algorithm: " + signatureAlgorithmOid);
            }

            String jcaDigestAlg = getJcaDigestAlgorithm(digestAlgorithmOid);
            // Canonical name for SHA-1 with ... is SHA1with, rather than SHA1. Same for all other
            // SHA algorithms.
            if (jcaDigestAlg.StartsWith("SHA-"))
            {
                jcaDigestAlg = "SHA" + jcaDigestAlg.Substring("SHA-".Length);
            }

            return jcaDigestAlg + "with" + suffix;
        }

        public static String getJcaDigestAlgorithm(String oid)
        {
            if (!OID_TO_JCA_DIGEST_ALG.TryGetValue(oid, out var result))
            {
                throw new CryptographicException("Unsupported digest algorithm: " + oid);
            }

            return result;
        }
    }
}