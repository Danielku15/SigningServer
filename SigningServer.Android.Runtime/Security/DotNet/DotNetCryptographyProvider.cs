using System.Security.Cryptography.X509Certificates;
using X509Certificate = SigningServer.Android.Security.Cert.X509Certificate;

namespace SigningServer.Android.Security.DotNet
{
    public class DotNetCryptographyProvider : CryptographyProvider
    {
        public static readonly DotNetCryptographyProvider INSTANCE = new DotNetCryptographyProvider();

        public Signature CreateSignature(string jcaSignatureAlgorithm)
        {
            return new DotNetSignature(jcaSignatureAlgorithm);
        }

        public PublicKey CreatePublicKey(X509Certificate2 rsaDotNet)
        {
            return new DotNetX509Certificate(rsaDotNet).GetPublicKey();
        }

        public PrivateKey CreatePrivateKey(X509Certificate2 rsaDotNet)
        {
            return new DotNetX509Certificate(rsaDotNet).GetPrivateKey();
        }

        public X509Certificate CreateCertificate(X509Certificate2 cert)
        {
            return new DotNetX509Certificate(cert);
        }
    }
}