using System;

namespace SigningServer.Android.Security.Cert
{
    public class CertificateEncodingException : CertificateException
    {
        public CertificateEncodingException()
        {
        }

        public CertificateEncodingException(string message) : base(message)
        {
        }

        public CertificateEncodingException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}