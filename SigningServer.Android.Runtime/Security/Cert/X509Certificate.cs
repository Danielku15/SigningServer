using System.Linq;
using SigningServer.Android.Math;

namespace SigningServer.Android.Security.Cert
{
    public abstract class X509Certificate : Certificate
    {
        public abstract X500Principal GetIssuerX500Principal();
        public abstract BigInteger GetSerialNumber();
        public abstract PublicKey GetPublicKey();
        public abstract bool HasUnsupportedCriticalExtension();
        public abstract bool[] GetKeyUsage();
        public abstract Principal GetSubjectDN();
        public abstract Principal GetIssuerDN();
        public abstract byte[] GetEncoded();

        public virtual bool Equals(X509Certificate other)
        {
            var thisCert = GetEncoded();
            var otherCert = other.GetEncoded();
            return thisCert.SequenceEqual(otherCert);
        }
    }
}