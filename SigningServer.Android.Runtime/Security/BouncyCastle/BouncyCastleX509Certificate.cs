using SigningServer.Android.Math;
using SigningServer.Android.Security.Cert;

namespace SigningServer.Android.Security.BouncyCastle
{
    internal class BouncyCastleX509Certificate : X509Certificate
    {
        private readonly Org.BouncyCastle.X509.X509Certificate _cert;

        public BouncyCastleX509Certificate( Org.BouncyCastle.X509.X509Certificate cert)
        {
            _cert = cert;
        }

        public override X500Principal GetIssuerX500Principal()
        {
            return new X500Principal(_cert.IssuerDN.GetEncoded());
        }

        public override byte[] GetEncoded()
        {
            return _cert.GetEncoded();
        }

        public override BigInteger GetSerialNumber()
        {
            return new BigInteger(_cert.SerialNumber);
        }

        public override PublicKey GetPublicKey()
        {
            return new BouncyCastlePublicKey(_cert.CertificateStructure.SubjectPublicKeyInfo.GetEncoded(), _cert.GetPublicKey());
        }

        public override bool HasUnsupportedCriticalExtension()
        {
            return false;
        }

        public override bool[] GetKeyUsage()
        {
            return _cert.GetKeyUsage();
        }

        public override Principal GetSubjectDN()
        {
            return new X500Principal(_cert.SubjectDN.GetEncoded());
        }

        public override Principal GetIssuerDN()
        {
            return GetIssuerX500Principal();
        }

    }
}
