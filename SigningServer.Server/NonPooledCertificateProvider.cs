using System;
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

    public Lazy<ValueTask<CertificateConfiguration>>? Get(string? username, string? password)
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

        return cert == null ? null : new Lazy<ValueTask<CertificateConfiguration>>(ValueTask.FromResult(cert));
    }

    public ValueTask ReturnAsync(string? username, Lazy<ValueTask<CertificateConfiguration>> certificateConfiguration)
    {
        return ValueTask.CompletedTask;
    }

    public ValueTask DestroyAsync(Lazy<ValueTask<CertificateConfiguration>>? certificateConfiguration)
    {
        return ValueTask.CompletedTask;
    }
}
