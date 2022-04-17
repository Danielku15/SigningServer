using SigningServer.Android.IO;
using SigningServer.Android.Security.BouncyCastle;

namespace SigningServer.Android.Security.Cert
{
    public abstract class CertificateFactory
    {
        public static CertificateFactory GetInstance(string s)
        {
            if (s == "X.509")
            {
                return new BouncyCastleX509CertificateFactory();
            }

            throw new CertificateException("Unsupported certificate type");
        }

        public abstract X509Certificate GenerateCertificate(InputStream input);
        public abstract Collections.Collection<Certificate> GenerateCertificates(InputStream input);
    }
}