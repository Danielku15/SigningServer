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
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Internal.X509;
using SigningServer.Android.Test.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Internal.Util
{
    [TestClass]
    public class X509CertificateUtilsTest
    {
        // The PEM and DER encodings of a certificate without redundant length bytes; since the
        // certificates are the same they have the same hex encoding of their digest.
        public static readonly String RSA_2048_VALID_PEM_ENCODING = "rsa-2048.x509.pem";
        public static readonly String RSA_2048_VALID_DER_ENCODING = "rsa-2048.x509.der";

        public static readonly String RSA_2048_VALID_DIGEST_HEX_ENCODING =
            "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8";

        // The PEM and DER encodings of a certificate with redundant length bytes; valid DER encodings
        // require that the length of contents within the encoding be specified with the minimum number
        // of bytes, but BER encodings allow redundant '00' bytes when specifying length.
        public static readonly String RSA_2048_REDUNDANT_LEN_BYTES_PEM_ENCODING =
            "rsa-2048-redun-len.x509.pem";

        public static readonly String RSA_2048_REDUNDANT_LEN_BYTES_DER_ENCODING =
            "rsa-2048-redun-len.x509.der";

        public static readonly String RSA_2048_REDUNDANT_LEN_DIGEST_HEX_ENCODING =
            "38481f124f8af6c36017abdfbefe375157ac304fb90adaa641ecba71b08dcd0f";

        // The PEM and DER encodings of both the valid and redundant length byte certificates above.
        public static readonly String RSA_2048_TWO_CERTS_PEM_ENCODING = "rsa-2048-2-certs.x509.pem";
        public static readonly String RSA_2048_TWO_CERTS_DER_ENCODING = "rsa-2048-2-certs.x509.der";

        [TestMethod]
        public void testGenerateCertificateWithValidPEMEncoding()
        {
            // The generateCertificate method should support both PEM and DER encodings; since the PEM
            // format is just the DER encoding base64'd with a header and a footer this test verifies
            // that a valid DER encoding in PEM format is successfully parsed and returns the expected
            // encoding.
            assertEquals(RSA_2048_VALID_DIGEST_HEX_ENCODING,
                getHexEncodedDigestOfCertFromResources(RSA_2048_VALID_PEM_ENCODING));
        }

        [TestMethod]
        public void testGenerateCertificateWithRedundantLengthBytesInPEMEncoding()
        {
            // This test verifies that a BER encoding of a certificate with redundant length bytes
            // can still be successfully parsed and returns the expected unmodified encoding.
            assertEquals(RSA_2048_REDUNDANT_LEN_DIGEST_HEX_ENCODING,
                getHexEncodedDigestOfCertFromResources(RSA_2048_REDUNDANT_LEN_BYTES_PEM_ENCODING));
        }

        [TestMethod]
        public void testGenerateCertificateWithValidDEREncoding()
        {
            // This test verifies the generateCertificate method successfully parses and returns the
            // expected encoding of a certificate with a valid DER encoding.
            assertEquals(RSA_2048_VALID_DIGEST_HEX_ENCODING,
                getHexEncodedDigestOfCertFromResources(RSA_2048_VALID_DER_ENCODING));
        }

        [TestMethod]
        public void testGenerateCertificateWithRedundantLengthBytesInDERENcoding()
        {
            // This test verifies the generateCertificate method successfully parses and returns the
            // original encoding of a certificate with redundant length bytes in the encoding.
            assertEquals(RSA_2048_REDUNDANT_LEN_DIGEST_HEX_ENCODING,
                getHexEncodedDigestOfCertFromResources(RSA_2048_REDUNDANT_LEN_BYTES_DER_ENCODING));
        }

        [TestMethod]
        public void testGenerateCertificatesWithTwoPEMEncodedCerts()
        {
            // The generateCertificates method accepts an InputStream which could contain zero or more
            // certificates in PEM or DER encoding; this test verifies both certificates in PEM format
            // are returned with the expected encodings.
            List<String> encodedCerts = getHexEncodedDigestsOfCertsFromResources(
                RSA_2048_TWO_CERTS_PEM_ENCODING);
            ISet<String> expectedEncodings = createSetOfValues(RSA_2048_VALID_DIGEST_HEX_ENCODING,
                RSA_2048_REDUNDANT_LEN_DIGEST_HEX_ENCODING);
            assertEncodingsMatchExpectedValues(encodedCerts, expectedEncodings);
        }

        [TestMethod]
        public void testGenerateCertificatesWithTwoDEREncodedCerts()
        {
            // This test verifies the generateCertificates method returns the expected encodings for
            // an InputStream with both DER encoded certificates.
            List<String> encodedCerts = getHexEncodedDigestsOfCertsFromResources(
                RSA_2048_TWO_CERTS_DER_ENCODING);
            ISet<String> expectedEncodings = createSetOfValues(RSA_2048_VALID_DIGEST_HEX_ENCODING,
                RSA_2048_REDUNDANT_LEN_DIGEST_HEX_ENCODING);
            assertEncodingsMatchExpectedValues(encodedCerts, expectedEncodings);
        }

        [TestMethod]
        public void testGenerateCertificateAndGenerateCertificatesReturnSameValues()
        {
            // The generateCertificates method is intended to read multiple certificates in the provided
            // InputStream, but it can also read a single certificate. Verify that both
            // generateCertificate and generateCertificates return the same encodings for the same
            // certificates.
            List<String> certResources = new List<string>
            {
                RSA_2048_VALID_PEM_ENCODING,
                RSA_2048_VALID_DER_ENCODING, RSA_2048_REDUNDANT_LEN_BYTES_PEM_ENCODING,
                RSA_2048_REDUNDANT_LEN_BYTES_DER_ENCODING
            };
            foreach (String certResource in certResources)
            {
                String genCertValue = getHexEncodedDigestOfCertFromResources(certResource);
                List<String> genCertsValues = getHexEncodedDigestsOfCertsFromResources(certResource);
                assertEquals(
                    "The generateCertificates method should have returned a single certificate", 1,
                    genCertsValues.Count);
                assertEquals(
                    "The hex encoded digest of the certificate from generateCertificate does not "
                    + "match the value from generateCertificates",
                    genCertValue, genCertsValues[0]);
            }
        }

        [TestMethod]
        public void testGenerateCertificatesWithEmptyInput()
        {
            // This test verifies the generateCertificates method returns an empty Collection of
            // Certificates when provided an empty InputStream.
            assertEquals(
                "Zero certificates should be returned when passing an empty InputStream to "
                + "generateCertificates",
                0, X509CertificateUtils.generateCertificates(
                    new MemoryStream(Array.Empty<byte>())).Count);
        }

        private static ISet<String> createSetOfValues(params String[] values)
        {
            return new HashSet<string>(values);
        }

        /**
         * Returns a hex encoding of the digest of the specified certificate from the resources.
         */
        private static String getHexEncodedDigestOfCertFromResources(String resourceName)
        {
            byte[] encodedForm = Resources.toByteArray("internal.util." + resourceName);
            X509Certificate cert = X509CertificateUtils.generateCertificate(encodedForm);
            return getHexEncodedDigestOfBytes(cert.getEncoded());
        }

        /**
         * Returns a list of hex encodings of the digests of the certificates in the specified resource.
         */
        private static List<String> getHexEncodedDigestsOfCertsFromResources(String resourceName)
        {
            Stream @in = Resources.toInputStream("internal.util." + resourceName);
            var certs = X509CertificateUtils.generateCertificates(@in);
            List<String> encodedCerts = new List<string>(certs.Count);
            foreach (var cert in
                     certs)
            {
                encodedCerts.Add(getHexEncodedDigestOfBytes(cert.getEncoded()));
            }

            return encodedCerts;
        }

        /**
         * Returns the hex encoding of the digest of the specified bytes.
         */
        private static String getHexEncodedDigestOfBytes(byte[] bytes)
        {
            var sha = SHA256.Create();
            return TestHelpers.encodeHex(sha.ComputeHash(bytes));
        }

        /**
         * Asserts that the encoding of the provided certificates match the expected values.
         */
        private static void assertEncodingsMatchExpectedValues(List<String> encodedCerts,
            ISet<String> expectedValues)
        {
            assertEquals(
                "The number of encoded certificates does not match the expected number of values",
                expectedValues.Count, encodedCerts.Count);
            foreach (String encodedCert in encodedCerts)
            {
                // if the current encoding is found in the expected Set then remove it to ensure that
                // duplicate values do not cause the test to pass if they are not expected.
                if (expectedValues.Contains(encodedCert))
                {
                    expectedValues.Remove(encodedCert);
                }
                else
                {
                    fail("An unexpected certificate with the following encoding was returned: "
                         + encodedCert);
                }
            }
        }
    }
}