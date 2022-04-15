using Org.BouncyCastle.X509;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security.BouncyCastle
{
    public class BouncyCastleX509KeyFactory : KeyFactory
    {
        public override PublicKey GeneratePublic(X509EncodedKeySpec keySpec)
        {
            return new BouncyCastlePublicKey(
                new X509CertificateParser().ReadCertificate(keySpec.GetEncoded().AsBytes()));
        }

        public override X509EncodedKeySpec GetKeySpec<T>(PublicKey publicKey)
        {
            return new X509EncodedKeySpec(publicKey.GetEncoded());
        }
    }
}