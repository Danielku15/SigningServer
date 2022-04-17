using System;
using System.Security.Cryptography;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetDsaPrivateKey : DotNetPrivateKey
    {
        private readonly DSA _privateKey;

        public DotNetDsaPrivateKey(DSA privateKey)
        {
            _privateKey = privateKey;
        }
        public byte[] GetEncoded()
        {
            throw new NotSupportedException("Access to raw private key not allowed");
        }

        public string GetFormat()
        {
            return "X.509";
        }

        public string GetAlgorithm()
        {
            return "DSA";
        }

        public byte[] SignHash(byte[] digest, HashAlgorithmName hashAlgorithmName)
        {
            return _privateKey.CreateSignature(digest);
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.Instance;
    }
}
