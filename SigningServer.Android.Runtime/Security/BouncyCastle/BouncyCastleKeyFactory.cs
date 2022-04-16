using Org.BouncyCastle.Security;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security.BouncyCastle
{
    internal class BouncyCastleKeyFactory : KeyFactory
    {
        public override PublicKey GeneratePublic(X509EncodedKeySpec keySpec)
        {
            return new BouncyCastlePublicKey(keySpec.GetEncoded(), PublicKeyFactory.CreateKey(keySpec.GetEncoded()));
        }

        public override X509EncodedKeySpec GetKeySpec<T>(PublicKey publicKey)
        {
            return new X509EncodedKeySpec(publicKey.GetEncoded());
        }

        public override PrivateKey GeneratePrivate(PKCS8EncodedKeySpec pkcs8EncodedKeySpec)
        {
            var key = PrivateKeyFactory.CreateKey(pkcs8EncodedKeySpec.GetEncoded());
            return new BouncyCastlePrivateKey(key);
        }
    }
}