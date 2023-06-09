using System;
using SigningServer.Server.Configuration;

namespace SigningServer.Server;

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
    Lazy<CertificateConfiguration> Get(string username, string password);
    
    /// <summary>
    /// Returns a certificate for usage by another party. 
    /// </summary>
    /// <param name="username">The username this certificate belongs to.</param>
    /// <param name="certificateConfiguration">The certificate configuration to return</param>
    void Return(string username, Lazy<CertificateConfiguration> certificateConfiguration);
    
    /// <summary>
    /// Destroys the given certificate because it appears to not be usable anymore. 
    /// </summary>
    /// <param name="certificateConfiguration">The certificate to destroy.</param>
    void Destroy(Lazy<CertificateConfiguration> certificateConfiguration);
}
