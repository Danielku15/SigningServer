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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.ApkSig.Internal.Pkcs7;
using SigningServer.Android.ApkSig.Internal.Util;

namespace SigningServer.Android.ApkSig.Internal.X509
{
    /**
     * X509 {@code Certificate} as specified in RFC 5280.
     */
    [Asn1Class(Type = Asn1Type.SEQUENCE)]
    public class Certificate
    {
        [Asn1Field(Index = 0, Type = Asn1Type.SEQUENCE)]
        public TBSCertificate certificate;

        [Asn1Field(Index = 1, Type = Asn1Type.SEQUENCE)]
        public AlgorithmIdentifier signatureAlgorithm;

        [Asn1Field(Index = 2, Type = Asn1Type.BIT_STRING)]
        public ByteBuffer signature;

        public static X509Certificate2 findCertificate(
            Collection<X509Certificate2> certs, SignerIdentifier id)
        {
            foreach (var cert in certs)
            {
                if (isMatchingCerticicate(cert, id))
                {
                    return cert;
                }
            }

            return null;
        }

        private static bool isMatchingCerticicate(X509Certificate2 cert, SignerIdentifier id)
        {
            if (id.issuerAndSerialNumber == null)
            {
                // Android doesn't support any other means of identifying the signing certificate
                return false;
            }

            IssuerAndSerialNumber issuerAndSerialNumber = id.issuerAndSerialNumber;
            byte[] encodedIssuer =
                ByteBufferUtils.toByteArray(issuerAndSerialNumber.issuer.getEncoded());
            BigInteger idSerialNumber = issuerAndSerialNumber.certificateSerialNumber;
            // TODO: check whether this comparison is really correct.
            return idSerialNumber.Equals(new BigInteger(cert.GetSerialNumber()))
                   && encodedIssuer.SequenceEqual(cert.IssuerName.RawData);
        }

        public static List<X509Certificate2> parseCertificates(
            List<Asn1OpaqueObject> encodedCertificates)
        {
            if (encodedCertificates.Count == 0)
            {
                return new List<X509Certificate2>();
            }

            var result = new List<X509Certificate2>(encodedCertificates.Count);
            for (int i = 0;
                 i < encodedCertificates.Count;
                 i++)
            {
                Asn1OpaqueObject encodedCertificate = encodedCertificates[i];
                X509Certificate2 certificate;
                byte[] encodedForm = ByteBufferUtils.toByteArray(encodedCertificate.getEncoded());
                try
                {
                    certificate = X509CertificateUtils.generateCertificate(encodedForm);
                }
                catch (CryptographicException e)
                {
                    throw new CryptographicException("Failed to parse certificate #" + (i + 1), e);
                }

                // Wrap the cert so that the result's getEncoded returns exactly the original
                // encoded form. Without this, getEncoded may return a different form from what was
                // stored in the signature. This is because some X509Certificate(Factory)
                // implementations re-encode certificates and/or some implementations of
                // X509Certificate.getEncoded() re-encode certificates.
                // TODO Check GuaranteedEncodedFormX509Certificate usage
                // certificate = new GuaranteedEncodedFormX509Certificate(certificate, encodedForm);
                result.Add(certificate);
            }

            return result;
        }
    }
}