using System.Linq;
using Org.BouncyCastle.X509;
using SigningServer.Android.Collections;
using SigningServer.Android.IO;
using SigningServer.Android.Security.Cert;
using X509Certificate = SigningServer.Android.Security.Cert.X509Certificate;

namespace SigningServer.Android.Security.BouncyCastle
{
    public class BouncyCastleX509CertificateFactory : CertificateFactory
    {
        private readonly X509CertificateParser mParser;

        public BouncyCastleX509CertificateFactory()
        {
            mParser = new X509CertificateParser();
        }
        
        public override X509Certificate GenerateCertificate(InputStream input)
        {
            return new BouncyCastleX509Certificate(mParser.ReadCertificate(input.AsStream()));
        }

        public override Collection<Certificate> GenerateCertificates(InputStream input)
        {
            return new List<Certificate>(mParser.ReadCertificates(input.AsStream()).OfType<Org.BouncyCastle.X509.X509Certificate>()
                .Select(c => new BouncyCastleX509Certificate(c)));
        }
    }
}