using System;
using System.Linq;
using SigningServer.Server.Configuration;

namespace SigningServer.Server;

public class NonPooledCertificateProvider : ICertificateProvider
{
    private readonly SigningServerConfiguration _configuration;

    public NonPooledCertificateProvider(SigningServerConfiguration configuration)
    {
        _configuration = configuration;
    }

    public Lazy<CertificateConfiguration> Get(string username, string password)
    {
        CertificateConfiguration cert;
        if (string.IsNullOrWhiteSpace(username))
        {
            cert = _configuration.Certificates.FirstOrDefault(c => c.IsAnonymous);
        }
        else
        {
            cert = _configuration.Certificates.FirstOrDefault(
                c => c.IsAuthorized(username, password));
        }

        return cert == null ? null : new Lazy<CertificateConfiguration>(cert);
    }

    public void Return(string username, Lazy<CertificateConfiguration> certificateConfiguration)
    {
    }

    public void Destroy(Lazy<CertificateConfiguration> certificateConfiguration)
    {
    }
}
