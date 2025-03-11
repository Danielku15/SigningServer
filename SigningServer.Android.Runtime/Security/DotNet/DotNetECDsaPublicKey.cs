using System.Security.Cryptography;
using SigningServer.Android.Math;
using SigningServer.Android.Security.Interfaces;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetECDsaPublicKey : DotNetPublicKey, ECKey
    {
        private readonly byte[] _encoded;
        private readonly ECDsa _publicKey;

        public DotNetECDsaPublicKey(byte[] encoded, ECDsa publicKey)
        {
            _encoded = encoded;
            _publicKey = publicKey;
        }

        public bool VerifyHash(byte[] digest, HashAlgorithmName digestName, byte[] signature)
        {
            return _publicKey.VerifyHash(digest, signature);
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
            return "EC";
        }

        public CryptographyProvider Provider => DotNetCryptographyProvider.Instance;

        public ECParameterSpec GetParams()
        {
            var p = _publicKey.ExportParameters(false);
            return new ECParameterSpec(new BigInteger(p.Curve.Order));
        }
    }
}
