using System.Security.Cryptography;
using SigningServer.Android.Math;
using SigningServer.Android.Security.Interfaces;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetRsaPublicKey : DotNetPublicKey, RSAKey
    {
        private readonly byte[] _encoded;
        private readonly RSA _publicKey;
        private readonly RSASignaturePadding _rsaSignaturePadding;

        public DotNetRsaPublicKey(
            byte[] encoded,
            RSA publicKey, RSASignaturePadding rsaSignaturePadding)
        {
            _encoded = encoded;
            _publicKey = publicKey;
            _rsaSignaturePadding = rsaSignaturePadding;
        }

        public bool VerifyHash(byte[] digest, HashAlgorithmName digestName, byte[] signature)
        {
            return _publicKey.VerifyHash(digest, signature, digestName, _rsaSignaturePadding);
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
            return "RSA";
        }

        public BigInteger GetModulus()
        {
            var key = _publicKey.ExportParameters(false);
            return new BigInteger(key.Modulus);
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.Instance;
    }
}
