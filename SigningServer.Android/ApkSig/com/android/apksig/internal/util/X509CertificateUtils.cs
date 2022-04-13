// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    /// <summary>
    /// Provides methods to generate {@code X509Certificate}s from their encoded form. These methods
    /// can be used to generate certificates that would be rejected by the Java {@code
    /// CertificateFactory}.
    /// </summary>
    public class X509CertificateUtils
    {
        internal static SigningServer.Android.Security.Cert.CertificateFactory sCertFactory = null;
        
        public static readonly sbyte[] BEGIN_CERT_HEADER = "-----BEGIN CERTIFICATE-----".GetBytes();
        
        public static readonly sbyte[] END_CERT_FOOTER = "-----END CERTIFICATE-----".GetBytes();
        
        internal static void BuildCertFactory()
        {
            if (SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.sCertFactory != null)
            {
                return;
            }
            try
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.sCertFactory = SigningServer.Android.Security.Cert.CertificateFactory.GetInstance("X.509");
            }
            catch (SigningServer.Android.Security.Cert.CertificateException e)
            {
                throw new SigningServer.Android.Core.RuntimeException("Failed to create X.509 CertificateFactory", e);
            }
        }
        
        /// <summary>
        /// Generates an {@code X509Certificate} from the {@code InputStream}.
        /// 
        /// @throws CertificateException if the {@code InputStream} cannot be decoded to a valid
        ///                              certificate.
        /// </summary>
        public static SigningServer.Android.Security.Cert.X509Certificate GenerateCertificate(SigningServer.Android.IO.InputStream input)
        {
            sbyte[] encodedForm;
            try
            {
                encodedForm = SigningServer.Android.Com.Android.Apksig.Internal.Util.ByteStreams.ToByteArray(input);
            }
            catch (SigningServer.Android.IO.IOException e)
            {
                throw new SigningServer.Android.Security.Cert.CertificateException("Failed to parse certificate", e);
            }
            return SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.GenerateCertificate(encodedForm);
        }
        
        /// <summary>
        /// Generates an {@code X509Certificate} from the encoded form.
        /// 
        /// @throws CertificateException if the encodedForm cannot be decoded to a valid certificate.
        /// </summary>
        public static SigningServer.Android.Security.Cert.X509Certificate GenerateCertificate(sbyte[] encodedForm)
        {
            if (SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.sCertFactory == null)
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.BuildCertFactory();
            }
            return SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.GenerateCertificate(encodedForm, SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.sCertFactory);
        }
        
        /// <summary>
        /// Generates an {@code X509Certificate} from the encoded form using the provided
        /// {@code CertificateFactory}.
        /// 
        /// @throws CertificateException if the encodedForm cannot be decoded to a valid certificate.
        /// </summary>
        public static SigningServer.Android.Security.Cert.X509Certificate GenerateCertificate(sbyte[] encodedForm, SigningServer.Android.Security.Cert.CertificateFactory certFactory)
        {
            SigningServer.Android.Security.Cert.X509Certificate certificate;
            try
            {
                certificate = (SigningServer.Android.Security.Cert.X509Certificate)certFactory.GenerateCertificate(new SigningServer.Android.IO.ByteArrayInputStream(encodedForm));
                return certificate;
            }
            catch (SigningServer.Android.Security.Cert.CertificateException e)
            {
            }
            try
            {
                SigningServer.Android.IO.ByteBuffer encodedCertBuffer = SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.GetNextDEREncodedCertificateBlock(SigningServer.Android.IO.ByteBuffer.Wrap(encodedForm));
                int startingPos = encodedCertBuffer.Position();
                SigningServer.Android.Com.Android.Apksig.Internal.X509.Certificate reencodedCert = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1BerParser.Parse(encodedCertBuffer, typeof(SigningServer.Android.Com.Android.Apksig.Internal.X509.Certificate));
                sbyte[] reencodedForm = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DerEncoder.Encode(reencodedCert);
                certificate = (SigningServer.Android.Security.Cert.X509Certificate)certFactory.GenerateCertificate(new SigningServer.Android.IO.ByteArrayInputStream(reencodedForm));
                sbyte[] originalEncoding = new sbyte[encodedCertBuffer.Position() - startingPos];
                encodedCertBuffer.Position(startingPos);
                encodedCertBuffer.Get(originalEncoding);
                SigningServer.Android.Com.Android.Apksig.Internal.Util.GuaranteedEncodedFormX509Certificate guaranteedEncodedCert = new SigningServer.Android.Com.Android.Apksig.Internal.Util.GuaranteedEncodedFormX509Certificate(certificate, originalEncoding);
                return guaranteedEncodedCert;
            }
            catch (System.Exception e) when ( e is SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DecodingException || e is SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1EncodingException || e is SigningServer.Android.Security.Cert.CertificateException)
            {
                throw new SigningServer.Android.Security.Cert.CertificateException("Failed to parse certificate", e);
            }
        }
        
        /// <summary>
        /// Generates a {@code Collection} of {@code Certificate} objects from the encoded {@code
        /// InputStream}.
        /// 
        /// @throws CertificateException if the InputStream cannot be decoded to zero or more valid
        ///                              {@code Certificate} objects.
        /// </summary>
        public static SigningServer.Android.Collections.Collection<SigningServer.Android.Security.Cert.Certificate> GenerateCertificates(SigningServer.Android.IO.InputStream input)
        {
            if (SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.sCertFactory == null)
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.BuildCertFactory();
            }
            return SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.GenerateCertificates(input, SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.sCertFactory);
        }
        
        /// <summary>
        /// Generates a {@code Collection} of {@code Certificate} objects from the encoded {@code
        /// InputStream} using the provided {@code CertificateFactory}.
        /// 
        /// @throws CertificateException if the InputStream cannot be decoded to zero or more valid
        ///                              {@code Certificates} objects.
        /// </summary>
        public static SigningServer.Android.Collections.Collection<SigningServer.Android.Security.Cert.Certificate> GenerateCertificates(SigningServer.Android.IO.InputStream input, SigningServer.Android.Security.Cert.CertificateFactory certFactory)
        {
            sbyte[] encodedCerts;
            try
            {
                encodedCerts = SigningServer.Android.Com.Android.Apksig.Internal.Util.ByteStreams.ToByteArray(input);
            }
            catch (SigningServer.Android.IO.IOException e)
            {
                throw new SigningServer.Android.Security.Cert.CertificateException("Failed to read the input stream", e);
            }
            try
            {
                return certFactory.GenerateCertificates(new SigningServer.Android.IO.ByteArrayInputStream(encodedCerts));
            }
            catch (SigningServer.Android.Security.Cert.CertificateException e)
            {
            }
            try
            {
                SigningServer.Android.Collections.Collection<SigningServer.Android.Security.Cert.X509Certificate> certificates = new SigningServer.Android.Collections.List<SigningServer.Android.Security.Cert.X509Certificate>(1);
                SigningServer.Android.IO.ByteBuffer encodedCertsBuffer = SigningServer.Android.IO.ByteBuffer.Wrap(encodedCerts);
                while (encodedCertsBuffer.HasRemaining())
                {
                    SigningServer.Android.IO.ByteBuffer certBuffer = SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.GetNextDEREncodedCertificateBlock(encodedCertsBuffer);
                    int startingPos = certBuffer.Position();
                    SigningServer.Android.Com.Android.Apksig.Internal.X509.Certificate reencodedCert = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1BerParser.Parse(certBuffer, typeof(SigningServer.Android.Com.Android.Apksig.Internal.X509.Certificate));
                    sbyte[] reencodedForm = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DerEncoder.Encode(reencodedCert);
                    SigningServer.Android.Security.Cert.X509Certificate certificate = (SigningServer.Android.Security.Cert.X509Certificate)certFactory.GenerateCertificate(new SigningServer.Android.IO.ByteArrayInputStream(reencodedForm));
                    sbyte[] originalEncoding = new sbyte[certBuffer.Position() - startingPos];
                    certBuffer.Position(startingPos);
                    certBuffer.Get(originalEncoding);
                    SigningServer.Android.Com.Android.Apksig.Internal.Util.GuaranteedEncodedFormX509Certificate guaranteedEncodedCert = new SigningServer.Android.Com.Android.Apksig.Internal.Util.GuaranteedEncodedFormX509Certificate(certificate, originalEncoding);
                    certificates.Add(guaranteedEncodedCert);
                }
                return certificates;
            }
            catch (System.Exception e) when ( e is SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DecodingException || e is SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1EncodingException)
            {
                throw new SigningServer.Android.Security.Cert.CertificateException("Failed to parse certificates", e);
            }
        }
        
        /// <summary>
        /// Parses the provided ByteBuffer to obtain the next certificate in DER encoding. If the buffer
        /// does not begin with the PEM certificate header then it is returned with the assumption that
        /// it is already DER encoded. If the buffer does begin with the PEM certificate header then the
        /// certificate data is read from the buffer until the PEM certificate footer is reached; this
        /// data is then base64 decoded and returned in a new ByteBuffer.
        /// 
        /// If the buffer is in PEM format then the position of the buffer is moved to the end of the
        /// current certificate; if the buffer is already DER encoded then the position of the buffer is
        /// not modified.
        /// 
        /// @throws CertificateException if the buffer contains the PEM certificate header but does not
        ///                              contain the expected footer.
        /// </summary>
        internal static SigningServer.Android.IO.ByteBuffer GetNextDEREncodedCertificateBlock(SigningServer.Android.IO.ByteBuffer certificateBuffer)
        {
            if (certificateBuffer == null)
            {
                throw new System.NullReferenceException("The certificateBuffer cannot be null");
            }
            if (certificateBuffer.Remaining() < SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.BEGIN_CERT_HEADER.Length)
            {
                return certificateBuffer;
            }
            certificateBuffer.Mark();
            for (int i = 0;i < SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.BEGIN_CERT_HEADER.Length;i++)
            {
                if (certificateBuffer.Get() != SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.BEGIN_CERT_HEADER[i])
                {
                    certificateBuffer.Reset();
                    return certificateBuffer;
                }
            }
            SigningServer.Android.Core.StringBuilder pemEncoding = new SigningServer.Android.Core.StringBuilder();
            while (certificateBuffer.HasRemaining())
            {
                char encodedChar = (char)certificateBuffer.Get();
                if (encodedChar == '-')
                {
                    break;
                }
                else if (SigningServer.Android.Core.CharExtensions.IsWhitespace(encodedChar))
                {
                    continue;
                }
                else 
                {
                    pemEncoding.Append(encodedChar);
                }
            }
            for (int i = 1;i < SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.END_CERT_FOOTER.Length;i++)
            {
                if (!certificateBuffer.HasRemaining())
                {
                    throw new SigningServer.Android.Security.Cert.CertificateException("The provided input contains the PEM certificate header but does not " + "contain sufficient data for the footer");
                }
                if (certificateBuffer.Get() != SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.END_CERT_FOOTER[i])
                {
                    throw new SigningServer.Android.Security.Cert.CertificateException("The provided input contains the PEM certificate header without a " + "valid certificate footer");
                }
            }
            sbyte[] derEncoding = SigningServer.Android.Util.Base64.GetDecoder().Decode(pemEncoding.ToString());
            int nextEncodedChar = certificateBuffer.Position();
            while (certificateBuffer.HasRemaining())
            {
                char trailingChar = (char)certificateBuffer.Get();
                if (SigningServer.Android.Core.CharExtensions.IsWhitespace(trailingChar))
                {
                    nextEncodedChar++;
                }
                else 
                {
                    break;
                }
            }
            certificateBuffer.Position(nextEncodedChar);
            return SigningServer.Android.IO.ByteBuffer.Wrap(derEncoding);
        }
        
    }
    
}
