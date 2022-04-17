using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using SigningServer.Android.Math;
using SigningServer.Android.Security.Interfaces;

namespace SigningServer.Android.Security.BouncyCastle
{
    internal class BouncyCastlePublicKey : PublicKey, RSAKey, DSAKey, ECKey, CryptographyProviderAccessor
    {
        private readonly byte[] mEncoded;

        public AsymmetricKeyParameter KeyParameter { get; }

        public BouncyCastlePublicKey(byte[] encoded, AsymmetricKeyParameter key)
        {
            mEncoded = encoded;
            KeyParameter = key;
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
            switch (KeyParameter)
            {
                case DsaKeyParameters _: return "DSA";
                case RsaKeyParameters _: return "RSA";
                case ECKeyParameters _: return "EC";
            }
            return KeyParameter.ToString();
        }

        public BigInteger GetModulus()
        {
            if (KeyParameter is RsaKeyParameters rsa)
            {
                return new BigInteger(rsa.Modulus);
            }

            throw new InvalidOperationException();
        }

        public ECParameterSpec GetParams()
        {
            if (KeyParameter is ECKeyParameters ec)
            {
                return new ECParameterSpec(new BigInteger(ec.Parameters.Curve.Order));
            }

            throw new InvalidOperationException();
        }

        public CryptographyProvider Provider => BouncyCastleCryptographyProvider.INSTANCE;
    }
}