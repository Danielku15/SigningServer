using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Server
{
    public class SigningCertificateFromPfxFile : SigningCertificateFromStore
    {
        public SigningCertificateFromPfxFile(string pfx, string password)
            : base(new X509Certificate2(pfx, password))
        {
        }
    }
}