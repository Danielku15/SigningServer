using SigningServer.Android.Security.BouncyCastle;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security
{
    public abstract class KeyFactory
    {
        // ReSharper disable once UnusedParameter.Global
        public static KeyFactory GetInstance(string keyAlgorithm)
        {
            return new BouncyCastleKeyFactory();
        }

        public abstract PublicKey GeneratePublic(X509EncodedKeySpec keySpec);

        public abstract X509EncodedKeySpec GetKeySpec<T>(PublicKey publicKey);

        public abstract PrivateKey GeneratePrivate(PKCS8EncodedKeySpec pkcs8EncodedKeySpec);
    }
}