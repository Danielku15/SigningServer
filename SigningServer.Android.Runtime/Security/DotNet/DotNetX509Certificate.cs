using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;
using SigningServer.Android.Math;
using SigningServer.Android.Security.Cert;
using X509Certificate = SigningServer.Android.Security.Cert.X509Certificate;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetX509Certificate : X509Certificate
    {
        private readonly X509Certificate2 _certificate;
        private readonly Org.BouncyCastle.X509.X509Certificate _bouncy;

        public DotNetX509Certificate(X509Certificate2 certificate)
        {
            _certificate = certificate;
            // we use BouncyCastle for most encoding operations
            _bouncy = new X509CertificateParser().ReadCertificate(certificate.GetRawCertData());
        }

        public override X500Principal GetIssuerX500Principal()
        {
            return new X500Principal(_certificate.IssuerName);
        }

        public override BigInteger GetSerialNumber()
        {
            return new BigInteger(_bouncy.SerialNumber);
        }
        
        public override PublicKey GetPublicKey()
        {
            var ecdsa = _certificate.GetECDsaPublicKey();
            if (ecdsa != null)
            {
                return new DotNetECDsaPublicKey(EncodedPublicKey(_bouncy), ecdsa);
            }

            var rsa = _certificate.GetRSAPublicKey();
            if (rsa != null)
            {
                return new DotNetRsaPublicKey(EncodedPublicKey(_bouncy), rsa, RSASignaturePadding.Pkcs1);
            }

            var dsa = _certificate.GetDSAPublicKey();
            if (dsa != null)
            {
                return new DotNetDsaPublicKey(EncodedPublicKey(_bouncy), dsa);
            }

            throw new CryptographicException("Unsupported public key type: " + _certificate.PublicKey.Oid);
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
            return _bouncy.GetKeyUsage();
        }

        public override Principal GetSubjectDN()
        {
            return new X500Principal(_certificate.SubjectName);
        }

        public override Principal GetIssuerDN()
        {
            return GetIssuerX500Principal();
        }

        public override byte[] GetEncoded()
        {
            return _bouncy.GetEncoded();
        }
    }
}
