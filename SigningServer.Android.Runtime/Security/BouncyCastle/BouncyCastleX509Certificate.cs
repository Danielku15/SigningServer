using SigningServer.Android.Math;
using SigningServer.Android.Security.Cert;

namespace SigningServer.Android.Security.BouncyCastle
{
    internal class BouncyCastleX509Certificate : X509Certificate
    {
        private readonly Org.BouncyCastle.X509.X509Certificate mCert;

        public BouncyCastleX509Certificate( Org.BouncyCastle.X509.X509Certificate cert)
        {
            mCert = cert;
        }

        public override X500Principal GetIssuerX500Principal()
        {
            return new X500Principal(mCert.IssuerDN.GetEncoded());
        }

        public override byte[] GetEncoded()
        {
            return mCert.GetEncoded();
        }

        public override BigInteger GetSerialNumber()
        {
            return new BigInteger(mCert.SerialNumber);
        }

        public override PublicKey GetPublicKey()
        {
            return new BouncyCastlePublicKey(mCert.CertificateStructure.SubjectPublicKeyInfo.GetEncoded(), mCert.GetPublicKey());
        }

        public override bool HasUnsupportedCriticalExtension()
        {
            return false;
        }

        public override bool[] GetKeyUsage()
        {
            return mCert.GetKeyUsage();
        }

        public override Principal GetSubjectDN()
        {
            return new X500Principal(mCert.SubjectDN.GetEncoded());
        }

        public override Principal GetIssuerDN()
        {
            return GetIssuerX500Principal();
        }

    }
}