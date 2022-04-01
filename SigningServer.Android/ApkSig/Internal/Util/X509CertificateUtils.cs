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
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Text;
using SigningServer.Android;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.ApkSig.Internal.X509;

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /**
     * Provides methods to generate {@code X509Certificate}s from their encoded form. These methods
     * can be used to generate certificates that would be rejected by the Java {@code
     * CertificateFactory}.
     */
    public class X509CertificateUtils
    {
        // The PEM certificate header and footer as specified in RFC 7468:
        //   There is exactly one space character (SP) separating the "BEGIN" or
        //   "END" from the label.  There are exactly five hyphen-minus (also
        //   known as dash) characters ("-") on both ends of the encapsulation
        //   boundaries, no more, no less.
        public static readonly byte[] BEGIN_CERT_HEADER = Encoding.Default.GetBytes("-----BEGIN CERTIFICATE-----");
        public static readonly byte[] END_CERT_FOOTER = Encoding.Default.GetBytes("-----END CERTIFICATE-----");

        /**
         * Generates an {@code X509Certificate} from the {@code InputStream}.
         *
         * @throws CertificateException if the {@code InputStream} cannot be decoded to a valid
         *                              certificate.
         */
        public static X509Certificate generateCertificate(Stream @in)
        {
            byte[] encodedForm;
            try
            {
                encodedForm = ByteStreams.toByteArray(@in);
            }
            catch (IOException e)
            {
                throw new CryptographicException("Failed to parse certificate", e);
            }

            return generateCertificate(encodedForm);
        }

        /**
         * Generates an {@code X509Certificate} from the encoded form.
         *
         * @throws CertificateException if the encodedForm cannot be decoded to a valid certificate.
         */
        public static X509Certificate generateCertificate(byte[] encodedForm)
        {
            X509Certificate certificate;
            try

            {
                certificate = new X509Certificate(encodedForm);
                return certificate;
            }
            catch (CryptographicException e)
            {
                // This could be expected if the certificate is encoded using a BER encoding that does
                // not use the minimum number of bytes to represent the length of the contents; attempt
                // to decode the certificate using the BER parser and re-encode using the DER encoder
                // below.
            }

            try
            {
                // Some apps were previously signed with a BER encoded certificate that now results
                // in exceptions from the CertificateFactory generateCertificate(s) methods. Since
                // the original BER encoding of the certificate is used as the signature for these
                // apps that original encoding must be maintained when signing updated versions of
                // these apps and any new apps that may require capabilities guarded by the
                // signature. To maintain the same signature the BER parser can be used to parse
                // the certificate, then it can be re-encoded to its DER equivalent which is
                // accepted by the generateCertificate method. The positions in the ByteBuffer can
                // then be used with the GuaranteedEncodedFormX509Certificate object to ensure the
                // getEncoded method returns the original signature of the app.
                ByteBuffer encodedCertBuffer = getNextDEREncodedCertificateBlock(
                    ByteBuffer.wrap(encodedForm));
                int startingPos = encodedCertBuffer.position();
                Certificate reencodedCert = Asn1BerParser.parse<Certificate>(encodedCertBuffer);
                byte[] reencodedForm = Asn1DerEncoder.encode(reencodedCert);
                certificate = new X509Certificate(reencodedForm);
                // If the reencodedForm is successfully accepted by the CertificateFactory then copy the
                // original encoding from the ByteBuffer and use that encoding in the Guaranteed object.
                byte[] originalEncoding = new byte[encodedCertBuffer.position() - startingPos];
                encodedCertBuffer.position(startingPos);
                encodedCertBuffer.get(originalEncoding);
                GuaranteedEncodedFormX509Certificate guaranteedEncodedCert =
                    new GuaranteedEncodedFormX509Certificate(certificate, originalEncoding);
                return guaranteedEncodedCert;
            }
            catch (Exception e) when (e is Asn1DecodingException || e is Asn1EncodingException ||
                                      e is CryptographicException)
            {
                throw new CryptographicException("Failed to parse certificate", e);
            }
        }

        /**
         * Generates a {@code Collection} of {@code Certificate} objects from the encoded {@code
         * InputStream}.
         *
         * @throws CertificateException if the InputStream cannot be decoded to zero or more valid
         *                              {@code Certificate} objects.
         */
        public static List<X509Certificate> generateCertificates(Stream @in)
        {
            var certificates = new List<X509Certificate>();

            // Since the InputStream is not guaranteed to support mark / reset operations first read it
            // into a byte array to allow using the BER parser / DER encoder if it cannot be read by
            // the CertificateFactory.
            byte[] encodedCerts;
            try

            {
                encodedCerts = ByteStreams.toByteArray(@in);
            }
            catch (IOException e)
            {
                throw new CryptographicException("Failed to read the input stream", e);
            }

            try
            {
                // TODO: support multiple certificates (seems API was only added in .net 5)
                var certificate = new X509Certificate(encodedCerts);
                certificates.Add(certificate);
                return certificates;
            }
            catch (CryptographicException e)
            {
                // This could be expected if the certificates are encoded using a BER encoding that does
                // not use the minimum number of bytes to represent the length of the contents; attempt
                // to decode the certificates using the BER parser and re-encode using the DER encoder
                // below.
            }

            try
            {
                ByteBuffer encodedCertsBuffer = ByteBuffer.wrap(encodedCerts);
                while (encodedCertsBuffer.hasRemaining())
                {
                    ByteBuffer certBuffer = getNextDEREncodedCertificateBlock(encodedCertsBuffer);
                    int startingPos = certBuffer.position();
                    Certificate reencodedCert = Asn1BerParser.parse<Certificate>(certBuffer);
                    byte[] reencodedForm = Asn1DerEncoder.encode(reencodedCert);
                    X509Certificate certificate = new X509Certificate(reencodedForm);
                    byte[] originalEncoding = new byte[certBuffer.position() - startingPos];
                    certBuffer.position(startingPos);
                    certBuffer.get(originalEncoding);
                    GuaranteedEncodedFormX509Certificate guaranteedEncodedCert =
                        new GuaranteedEncodedFormX509Certificate(certificate, originalEncoding);
                    certificates.Add(guaranteedEncodedCert);
                }

                return certificates;
            }
            catch (Exception e) when (e is Asn1DecodingException || e is Asn1EncodingException)
            {
                throw new CryptographicException("Failed to parse certificates", e);
            }
        }

        /**
         * Parses the provided ByteBuffer to obtain the next certificate in DER encoding. If the buffer
         * does not begin with the PEM certificate header then it is returned with the assumption that
         * it is already DER encoded. If the buffer does begin with the PEM certificate header then the
         * certificate data is read from the buffer until the PEM certificate footer is reached; this
         * data is then base64 decoded and returned in a new ByteBuffer.
         *
         * If the buffer is in PEM format then the position of the buffer is moved to the end of the
         * current certificate; if the buffer is already DER encoded then the position of the buffer is
         * not modified.
         *
         * @throws CertificateException if the buffer contains the PEM certificate header but does not
         *                              contain the expected footer.
         */
        private static ByteBuffer getNextDEREncodedCertificateBlock(ByteBuffer certificateBuffer)
        {
            if (certificateBuffer == null)
            {
                throw new ArgumentNullException(nameof(certificateBuffer));
            }

            // if the buffer does not contain enough data for the PEM cert header then just return the
            // provided buffer.
            if (certificateBuffer.remaining() < BEGIN_CERT_HEADER.Length)
            {
                return certificateBuffer;
            }

            certificateBuffer.mark();
            for (int i = 0;
                 i < BEGIN_CERT_HEADER.Length;
                 i++)
            {
                if (certificateBuffer.get() != BEGIN_CERT_HEADER[i])
                {
                    certificateBuffer.reset();
                    return certificateBuffer;
                }
            }

            StringBuilder pemEncoding = new StringBuilder();
            while (certificateBuffer.hasRemaining())
            {
                char encodedChar = (char)certificateBuffer.get();
                // if the current character is a '-' then the beginning of the footer has been reached
                if (encodedChar == '-')
                {
                    break;
                }
                else if (char.IsWhiteSpace(encodedChar))
                {
                    continue;
                }
                else
                {
                    pemEncoding.Append(encodedChar);
                }
            }

            // start from the second index in the certificate footer since the first '-' should have
            // been consumed above.
            for (int i = 1; i < END_CERT_FOOTER.Length; i++)
            {
                if (!certificateBuffer.hasRemaining())
                {
                    throw new CryptographicException(
                        "The provided input contains the PEM certificate header but does not "
                        + "contain sufficient data for the footer");
                }

                if (certificateBuffer.get() != END_CERT_FOOTER[i])
                {
                    throw new CryptographicException(
                        "The provided input contains the PEM certificate header without a "
                        + "valid certificate footer");
                }
            }

            byte[] derEncoding = Convert.FromBase64String(pemEncoding.ToString());
            // consume any trailing whitespace in the byte buffer
            int nextEncodedChar = certificateBuffer.position();
            while (certificateBuffer.hasRemaining())
            {
                char trailingChar = (char)certificateBuffer.get();
                if (char.IsWhiteSpace(trailingChar))
                {
                    nextEncodedChar++;
                }
                else
                {
                    break;
                }
            }

            certificateBuffer.position(nextEncodedChar);
            return ByteBuffer.wrap(derEncoding);
        }
    }
}