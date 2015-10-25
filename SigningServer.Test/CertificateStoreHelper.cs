using System;
using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Test
{
    public sealed class CertificateStoreHelper : IDisposable
    {
        public X509Certificate2 Certificate { get; }
        public X509Store Store { get; private set; }

        public CertificateStoreHelper(string certificateFile, StoreName name, StoreLocation location)
            : this(new X509Certificate2(certificateFile), name, location)
        {
        }

        public CertificateStoreHelper(X509Certificate2 certificate, StoreName name, StoreLocation location)
        {
            Certificate = certificate;
            Store = new X509Store(name, location);
            Store.Open(OpenFlags.ReadWrite);
            Store.Add(certificate);
        }

        public void Dispose()
        {
            if (Store != null)
            {
                Store.Remove(Certificate);
                Store.Dispose();
                Store = null;
            }
        }
    }
}
