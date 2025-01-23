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
        CertificateAccessCredentials? credentials;
        if (string.IsNullOrWhiteSpace(username))
        {
            cert = _configuration.Certificates.FirstOrDefault(c => c.IsAnonymous);
            credentials = CertificateAccessCredentials.Anonymous;
        }
        else
        {
            var authResult = _configuration.Certificates
                .Select(c => (configuration: c, credentials: c.IsAuthorized(username, password)))
                .FirstOrDefault(c => c.credentials != null);

            cert = authResult.configuration;
            credentials = authResult.credentials;
        }

        return cert == null ? null : new NonPooledCertificateAccessor(credentials!, cert);
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
        public CertificateAccessCredentials Credentials { get; }
        public string CertificateName { get; }

        public NonPooledCertificateAccessor(
            CertificateAccessCredentials credentials,
            CertificateConfiguration certificateConfiguration)
        {
            Credentials = credentials;
            _certificateConfiguration = certificateConfiguration;
            CertificateName = certificateConfiguration.DisplayName;
        }

        public ValueTask<CertificateConfiguration> UseCertificate()
        {
            return ValueTask.FromResult(_certificateConfiguration);
        }
    }
}
