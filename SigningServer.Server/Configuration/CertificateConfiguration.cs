using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using SigningServer.Server.Util;

namespace SigningServer.Server.Configuration;

/// <summary>
/// A single certificate configuration.
/// </summary>
public class CertificateConfiguration
{
    /// <summary>
    /// The plain text username to use this certificate
    /// </summary>
    public string Username { get; set; }
    
    /// <summary>
    /// The plain text password to use this certificate
    /// </summary>
    public string Password { get; set; }

    /// <summary>
    /// Local Certificate from Certificate Store
    /// </summary>
    public LocalStoreCertificateConfiguration LocalStore { get; set; }

    /// <summary>
    /// Azure specific configuration
    /// </summary>
    public AzureKeyVaultConfiguration Azure { get; set; }

    /// <summary>
    /// The loaded certificate.
    /// </summary>
    [JsonIgnore] public X509Certificate2 Certificate { get; set; }
    
    /// <summary>
    /// The loaded private key.
    /// </summary>
    [JsonIgnore] public AsymmetricAlgorithm PrivateKey { get; set; }

    /// <summary>
    /// A value indicating whether authentication is needed for the certificate.
    /// </summary>
    [JsonIgnore] public bool IsAnonymous => string.IsNullOrWhiteSpace(Username);

    public void LoadCertificate(ILogger<CertificateConfiguration> logger, HardwareCertificateUnlocker unlocker)
    {
        // only do reloads if cert needs hardware unlock or certificate is not loaded at all
        if (string.IsNullOrEmpty(LocalStore?.TokenPin) && Certificate != null)
        {
            return;
        }

        Certificate?.Dispose();

        if (!string.IsNullOrEmpty(Azure?.KeyVaultUrl))
        {
            Azure.Load(logger, this);
        }
        else if(LocalStore != null)
        {
            LocalStore.Load(logger, this, unlocker);
        }
        else
        {
            throw new InvalidConfigurationException(
                "There is a wrongly configured certificate in the configuration, no Azure or LocalStore configuration found");
        }
    }

    public bool IsAuthorized(string username, string password)
    {
        return string.Equals(Username, username, StringComparison.CurrentCultureIgnoreCase) && Password == password;
    }

    public override string ToString()
    {
        if (LocalStore?.Thumbprint != null)
        {
            return $"User: {Username}, Local: {LocalStore}";
        }
        if (Azure?.CertificateName != null)
        {
            return $"User: {Username}, Local: {Azure}";
        }

        return $"User: {Username}, Unknown certificate";
    }
}
