using SigningServer.Android.Math;

namespace SigningServer.Android.Security.Cert
{
    public interface Certificate
    {
        sbyte[] GetEncoded();
    }

    public interface X509Certificate : Certificate
    {
        X500Principal GetIssuerX500Principal();
        BigInteger GetSerialNumber();
        PublicKey GetPublicKey();
        bool HasUnsupportedCriticalExtension();
        bool[] GetKeyUsage();
        Principal GetSubjectDN();
        Principal GetIssuerDN();
        bool Equals(X509Certificate other);
    }
}