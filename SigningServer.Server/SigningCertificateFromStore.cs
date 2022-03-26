using System.Security.Cryptography.X509Certificates;
using SigningServer.Contracts;

namespace SigningServer.Server
{
    public class SigningCertificateFromStore : ISigningCertificate
    {
        private readonly X509Certificate2 _certificate;

        public SigningCertificateFromStore(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        public string SubjectName => _certificate.SubjectName.Name;

        public byte[] GetRawCertData()
        {
            return _certificate.GetRawCertData();
        }

        public X509Certificate2 ToX509()
        {
            return _certificate;
        }

        public void Dispose()
        {
            _certificate.Dispose();
        }
    }
}