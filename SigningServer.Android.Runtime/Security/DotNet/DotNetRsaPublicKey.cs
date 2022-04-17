using System.Security.Cryptography;
using SigningServer.Android.Math;
using SigningServer.Android.Security.Interfaces;

namespace SigningServer.Android.Security.DotNet
{
    public class DotNetRsaPublicKey : DotNetPublicKey, RSAKey
    {
        private readonly byte[] mEncoded;
        private readonly RSA mPublicKey;
        private readonly RSASignaturePadding mRsaSignaturePadding;

        public DotNetRsaPublicKey(
            byte[] encoded,
            RSA publicKey, RSASignaturePadding rsaSignaturePadding)
        {
            mEncoded = encoded;
            mPublicKey = publicKey;
            mRsaSignaturePadding = rsaSignaturePadding;
        }

        public bool VerifyHash(byte[] digest, HashAlgorithmName digestName, byte[] signature)
        {
            return mPublicKey.VerifyHash(digest, signature, digestName, mRsaSignaturePadding);
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
            return "RSA";
        }

        public BigInteger GetModulus()
        {
            var key = mPublicKey.ExportParameters(false);
            return new BigInteger(key.Modulus);
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.INSTANCE;
    }
}