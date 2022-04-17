using System;
using System.Security.Cryptography;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetRsaPrivateKey : DotNetPrivateKey
    {
        private readonly RSASignaturePadding _padding;

        public RSA PrivateKey { get; }

        public DotNetRsaPrivateKey(RSA privateKey, RSASignaturePadding padding)
        {
            PrivateKey = privateKey;
            _padding = padding;
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
            return "RSA";
        }

        public byte[] SignHash(byte[] digest, HashAlgorithmName hashAlgorithmName)
        {
            return PrivateKey.SignHash(digest, hashAlgorithmName, _padding);
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.Instance;
    }
}
