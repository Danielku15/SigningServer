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

    public CertificateConfiguration Get(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return _configuration.Certificates.FirstOrDefault(c => c.IsAnonymous);
        }

        return _configuration.Certificates.FirstOrDefault(
            c => c.IsAuthorized(username, password));
    }

    public void Return(string username, CertificateConfiguration certificateConfiguration)
    {
    }
    
    public void Destroy(CertificateConfiguration certificateConfiguration)
    {
    }
}
