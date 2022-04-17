using System;

namespace SigningServer.Android.Security.Cert
{
    internal class CertificateException : GeneralSecurityException
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