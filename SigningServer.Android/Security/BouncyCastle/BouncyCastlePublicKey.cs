using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace SigningServer.Android.Security.BouncyCastle
{
    public class BouncyCastlePublicKey : PublicKey
    {
        private readonly X509Certificate mCert;

        public AsymmetricKeyParameter KeyParameter => mCert.GetPublicKey();

        public BouncyCastlePublicKey(X509Certificate cert)
        {
            mCert = cert;
        }

        public sbyte[] GetEncoded()
        {
            return mCert.GetEncoded().AsSBytes();
        }

        public string GetFormat()
        {
            return "X.509";
        }

        public string GetAlgorithm()
        {
            switch (mCert.GetPublicKey())
            {
                case DsaKeyParameters _: return "DSA";
                case RsaKeyParameters _: return "RSA";
                case ECKeyParameters _: return "EC";
            }
            return mCert.SigAlgName;
        }
    }
}