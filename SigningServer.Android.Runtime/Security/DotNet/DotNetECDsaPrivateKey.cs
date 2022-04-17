using System;
using System.Security.Cryptography;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetECDsaPrivateKey : DotNetPrivateKey
    {
        private readonly ECDsa _privateKey;

        public DotNetECDsaPrivateKey(ECDsa privateKey)
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
            return "EC";
        }

        public byte[] SignHash(byte[] digest, HashAlgorithmName hashAlgorithmName)
        {
            return _privateKey.SignHash(digest);
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.Instance;
    }
}
