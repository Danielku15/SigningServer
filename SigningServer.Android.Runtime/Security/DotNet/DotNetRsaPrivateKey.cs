using System;
using System.Security.Cryptography;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetRsaPrivateKey : DotNetPrivateKey
    {
        private readonly RSA mPrivateKey;
        private readonly RSASignaturePadding mPadding;

        public RSA PrivateKey => mPrivateKey;

        public DotNetRsaPrivateKey(RSA privateKey, RSASignaturePadding padding)
        {
            mPrivateKey = privateKey;
            mPadding = padding;
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
            return mPrivateKey.SignHash(digest, hashAlgorithmName, mPadding);
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.INSTANCE;
    }
}