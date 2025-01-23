using System.Linq;
using System.Threading.Tasks;
using SigningServer.Server.Configuration;
using SigningServer.Signing.Configuration;

namespace SigningServer.Server;

public class NonPooledCertificateProvider : ICertificateProvider
{
    private readonly SigningServerConfiguration _configuration;

    public NonPooledCertificateProvider(SigningServerConfiguration configuration)
    {
        _configuration = configuration;
    }

    public ICertificateAccessor? Get(string? username, string? password)
    {
        CertificateConfiguration? cert;
        if (string.IsNullOrWhiteSpace(username))
        {
            cert = _configuration.Certificates.FirstOrDefault(c => c.IsAnonymous);
        }
        else
        {
            cert = _configuration.Certificates.FirstOrDefault(
                c => c.IsAuthorized(username, password));
        }

        return cert == null ? null : new NonPooledCertificateAccessor(cert);
    }

    public ValueTask ReturnAsync(string? username, ICertificateAccessor certificateConfiguration)
    {
        return ValueTask.CompletedTask;
    }

    public ValueTask DestroyAsync(ICertificateAccessor? certificateConfiguration)
    {
        return ValueTask.CompletedTask;
    }

    private class NonPooledCertificateAccessor : ICertificateAccessor
    {
        private readonly CertificateConfiguration _certificateConfiguration;
        public string CertificateName { get; }

        public NonPooledCertificateAccessor(CertificateConfiguration certificateConfiguration)
        {
            _certificateConfiguration = certificateConfiguration;
            CertificateName = !string.IsNullOrEmpty(certificateConfiguration.CertificateName) 
                    ? certificateConfiguration.CertificateName
                    : certificateConfiguration.Username ?? "default";
        }

        public ValueTask<CertificateConfiguration> UseCertificate()
        {
            return ValueTask.FromResult(_certificateConfiguration);
        }
    }
}
