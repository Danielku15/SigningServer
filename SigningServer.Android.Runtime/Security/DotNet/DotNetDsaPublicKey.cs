using System.Security.Cryptography;
using SigningServer.Android.Security.Interfaces;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetDsaPublicKey : DotNetPublicKey, DSAKey
    {
        private readonly byte[] _encoded;
        private readonly DSA _publicKey;

        public DotNetDsaPublicKey(byte[] encoded, DSA publicKey)
        {
            _encoded = encoded;
            _publicKey = publicKey;
        }

        public bool VerifyHash(byte[] digest, HashAlgorithmName digestName, byte[] signature)
        {
            return _publicKey.VerifySignature(digest, signature);
        }

        public byte[] GetEncoded()
        {
            return _encoded;
        }

        public string GetFormat()
        {
            return "X.509";
        }

        public string GetAlgorithm()
        {
            return "DSA";
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.Instance;
    }
}
