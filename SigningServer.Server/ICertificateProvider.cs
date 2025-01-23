using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using SigningServer.Server.Configuration;
using SigningServer.Signing.Configuration;

namespace SigningServer.Server;

/// <summary>
/// A certificate accessor to getting metadata or the certificate itself.
/// </summary>
public interface ICertificateAccessor
{
    public string CertificateName { get; }
    ValueTask<CertificateConfiguration> UseCertificate();
}

/// <summary>
/// Represents a provider for certificates to use during signing.
/// </summary>
public interface ICertificateProvider
{
    /// <summary>
    /// Obtains a new certificate for usage during signing. 
    /// </summary>
    /// <param name="username">The username to select the certificate</param>
    /// <param name="password">The password to select the certificate</param>
    /// <returns>A certificate configuration to use for signing</returns>
    ICertificateAccessor? Get(string? username, string? password);
    
    /// <summary>
    /// Returns a certificate for usage by another party. 
    /// </summary>
    /// <param name="username">The username this certificate belongs to.</param>
    /// <param name="certificateConfiguration">The certificate configuration to return</param>
    ValueTask ReturnAsync(string? username, ICertificateAccessor certificateConfiguration);
    
    /// <summary>
    /// Destroys the given certificate because it appears to not be usable anymore. 
    /// </summary>
    /// <param name="certificateConfiguration">The certificate to destroy.</param>
    ValueTask DestroyAsync(ICertificateAccessor? certificateConfiguration);
}
