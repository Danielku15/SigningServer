using System.Security.Cryptography;
using SigningServer.Android.Math;
using SigningServer.Android.Security.Interfaces;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetECDsaPublicKey : DotNetPublicKey, ECKey
    {
        private readonly byte[] mEncoded;
        private readonly ECDsa mPublicKey;

        public DotNetECDsaPublicKey(byte[] encoded, ECDsa publicKey)
        {
            mEncoded = encoded;
            mPublicKey = publicKey;
        }

        public bool VerifyHash(byte[] digest, HashAlgorithmName digestName, byte[] signature)
        {
            return mPublicKey.VerifyHash(digest, signature);
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
            return "EC";
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.INSTANCE;

        public ECParameterSpec GetParams()
        {
            var p = mPublicKey.ExportParameters(false);
            return new ECParameterSpec(new BigInteger(p.Curve.Order));
        }
    }
}