using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace SigningServer.Android.Security.BouncyCastle
{
    public class BouncyCastleCryptographyProvider : CryptographyProvider
    {
        public static readonly BouncyCastleCryptographyProvider Instance = new BouncyCastleCryptographyProvider();

        public Signature CreateSignature(string jcaSignatureAlgorithm)
        {
            return new BouncyCastleSignature(jcaSignatureAlgorithm);
        }

        public PublicKey CreatePublicKey(X509Certificate certificate)
        {
            return new BouncyCastleX509Certificate(certificate).GetPublicKey();
        }

        public PrivateKey CreatePrivateKey(AsymmetricKeyParameter key)
        {
            return new BouncyCastlePrivateKey(key);
        }

        public Cert.X509Certificate CreateCertificate(X509Certificate cert)
        {
            return new BouncyCastleX509Certificate(cert);
        }
    }
}
