using System.Linq;
using SigningServer.Android.Math;
using SigningServer.Android.Security.Cert;

namespace SigningServer.Android.Security.BouncyCastle
{
    public class BouncyCastleX509Certificate : X509Certificate
    {
        private readonly Org.BouncyCastle.X509.X509Certificate mCert;

        public BouncyCastleX509Certificate(Org.BouncyCastle.X509.X509Certificate cert)
        {
            mCert = cert;
        }

        public X500Principal GetIssuerX500Principal()
        {
            return new X500Principal(mCert.IssuerDN.GetEncoded().AsSBytes());
        }

        public sbyte[] GetEncoded()
        {
            return mCert.GetEncoded().AsSBytes();
        }

        public BigInteger GetSerialNumber()
        {
            return new BigInteger(mCert.SerialNumber);
        }

        public PublicKey GetPublicKey()
        {
            return new BouncyCastlePublicKey(mCert);
        }

        public bool HasUnsupportedCriticalExtension()
        {
            return false;
        }

        public bool[] GetKeyUsage()
        {
            return mCert.GetKeyUsage();
        }

        public Principal GetSubjectDN()
        {
            return new X500Principal(mCert.SubjectDN.GetEncoded().AsSBytes());
        }

        public Principal GetIssuerDN()
        {
            return GetIssuerX500Principal();
        }

        public bool Equals(X509Certificate other)
        {
            var thisCert = GetEncoded();
            var otherCert = other.GetEncoded();
            return thisCert.SequenceEqual(otherCert);
        }
    }
}