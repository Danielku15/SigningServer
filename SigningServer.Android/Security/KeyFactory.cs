using System;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security
{
    public class KeyFactory
    {
        public static KeyFactory GetInstance(string keyAlgorithm)
        {
            throw new System.NotImplementedException();
        }

        public PublicKey GeneratePublic(X509EncodedKeySpec x509EncodedKeySpec)
        {
            throw new System.NotImplementedException();
        }

        public T GetKeySpec<T>(PublicKey publicKey) where T: KeySpec
        {
            throw new NotImplementedException();
        }
    }
}