using System.Linq;
using Org.BouncyCastle.X509;
using SigningServer.Android.Collections;
using SigningServer.Android.IO;
using SigningServer.Android.Security.Cert;
using X509Certificate = SigningServer.Android.Security.Cert.X509Certificate;

namespace SigningServer.Android.Security.BouncyCastle
{
    internal class BouncyCastleX509CertificateFactory : CertificateFactory
    {
        private readonly X509CertificateParser _parser;

        public BouncyCastleX509CertificateFactory()
        {
            _parser = new X509CertificateParser();
        }
        
        public override X509Certificate GenerateCertificate(InputStream input)
        {
            return new BouncyCastleX509Certificate(_parser.ReadCertificate(input.AsStream()));
        }

        public override Collection<Certificate> GenerateCertificates(InputStream input)
        {
            return new List<Certificate>(_parser.ReadCertificates(input.AsStream()).OfType<Org.BouncyCastle.X509.X509Certificate>()
                .Select(c => new BouncyCastleX509Certificate(c)));
        }
    }
}
