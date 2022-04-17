using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;
using SigningServer.Android.Math;
using SigningServer.Android.Security.Cert;
using X509Certificate = SigningServer.Android.Security.Cert.X509Certificate;

namespace SigningServer.Android.Security.DotNet
{
    public class DotNetX509Certificate : X509Certificate
    {
        private readonly X509Certificate2 mCertificate;
        private readonly Org.BouncyCastle.X509.X509Certificate mBouncy;

        public DotNetX509Certificate(X509Certificate2 certificate)
        {
            mCertificate = certificate;
            // we use BouncyCastle for most encoding operations
            mBouncy = DotNetUtilities.FromX509Certificate(certificate);
        }

        public override X500Principal GetIssuerX500Principal()
        {
            return new X500Principal(mCertificate.IssuerName);
        }

        public override BigInteger GetSerialNumber()
        {
            return new BigInteger(mBouncy.SerialNumber);
        }

        public PrivateKey GetPrivateKey()
        {
            var ecdsa = mCertificate.GetECDsaPrivateKey();
            if (ecdsa != null)
            {
                return new DotNetECDsaPrivateKey(ecdsa);
            }

            var rsa = mCertificate.GetRSAPrivateKey();
            if (rsa != null)
            {
                return new DotNetRsaPrivateKey(rsa, RSASignaturePadding.Pkcs1);
            }

            var dsa = mCertificate.GetDSAPrivateKey();
            if (dsa != null)
            {
                return new DotNetDsaPrivateKey(dsa);
            }

            throw new CryptographicException("Unsupported private key of certificate");
        }

        public override PublicKey GetPublicKey()
        {
            var ecdsa = mCertificate.GetECDsaPublicKey();
            if (ecdsa != null)
            {
                return new DotNetECDsaPublicKey(EncodedPublicKey(mBouncy), ecdsa);
            }

            var rsa = mCertificate.GetRSAPublicKey();
            if (rsa != null)
            {
                return new DotNetRsaPublicKey(EncodedPublicKey(mBouncy), rsa, RSASignaturePadding.Pkcs1);
            }

            var dsa = mCertificate.GetDSAPublicKey();
            if (dsa != null)
            {
                return new DotNetDsaPublicKey(EncodedPublicKey(mBouncy), dsa);
            }

            throw new CryptographicException("Unsupported public key type: " + mCertificate.PublicKey.Key);
        }

        private static byte[] EncodedPublicKey(Org.BouncyCastle.X509.X509Certificate certificate)
        {
            return certificate.CertificateStructure.SubjectPublicKeyInfo.GetEncoded();
        }

        public override bool HasUnsupportedCriticalExtension()
        {
            return false;
        }

        public override bool[] GetKeyUsage()
        {
            return mBouncy.GetKeyUsage();
        }

        public override Principal GetSubjectDN()
        {
            return new X500Principal(mCertificate.SubjectName);
        }

        public override Principal GetIssuerDN()
        {
            return GetIssuerX500Principal();
        }

        public override byte[] GetEncoded()
        {
            return mBouncy.GetEncoded();
        }
    }
}