using System.Security.Cryptography;
using SigningServer.Android.Security.Interfaces;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetDsaPublicKey : DotNetPublicKey, DSAKey
    {
        private readonly byte[] mEncoded;
        private readonly DSA mPublicKey;

        public DotNetDsaPublicKey(byte[] encoded, DSA publicKey)
        {
            mEncoded = encoded;
            mPublicKey = publicKey;
        }

        public bool VerifyHash(byte[] digest, HashAlgorithmName digestName, byte[] signature)
        {
            return mPublicKey.VerifySignature(digest, signature);
        }

        public byte[] GetEncoded()
        {
            return mEncoded;
        }

        public string GetFormat()
        {
            return "X.509";
        }

        public string GetAlgorithm()
        {
            return "DSA";
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.INSTANCE;
    }
}