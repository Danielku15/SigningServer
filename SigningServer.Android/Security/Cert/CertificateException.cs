using System;

namespace SigningServer.Android.Security.Cert
{
    public class CertificateException : GeneralSecurityException
    {
        public CertificateException()
        {
        }

        public CertificateException(string message) : base(message)
        {
        }

        public CertificateException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}