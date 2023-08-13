using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace SigningServer.Signing.Configuration;

/// <summary>
/// A single certificate configuration.
/// </summary>
public class CertificateConfiguration
{
    /// <summary>
    /// The plain text username to use this certificate
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// The plain text password to use this certificate
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Local Certificate from Certificate Store
    /// </summary>
    public LocalStoreCertificateConfiguration? LocalStore { get; set; }

    /// <summary>
    /// Azure specific configuration
    /// </summary>
    public AzureKeyVaultConfiguration? Azure { get; set; }

    /// <summary>
    /// Signing Server specific configuration
    /// </summary>
    public SigningServerApiConfiguration? SigningServer { get; set; }

    /// <summary>
    /// The loaded certificate.
    /// </summary>
    [JsonIgnore]
    public X509Certificate2? Certificate { get; set; }

    /// <summary>
    /// The loaded private key.
    /// </summary>
    [JsonIgnore]
    public AsymmetricAlgorithm? PrivateKey { get; set; }

    /// <summary>
    /// A value indicating whether authentication is needed for the certificate.
    /// </summary>
    [JsonIgnore]
    public bool IsAnonymous => string.IsNullOrWhiteSpace(Username);

    public void LoadCertificate(ILogger logger, IHardwareCertificateUnlocker? unlocker)
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
        else if (LocalStore != null)
        {
            LocalStore.Load(logger, this, unlocker);
        }
        else if (SigningServer != null)
        {
            SigningServer.Load(logger, this);
        }
        else
        {
            throw new InvalidConfigurationException(
                "There is a wrongly configured certificate in the configuration, no Azure or LocalStore configuration found");
        }
    }

    public bool IsAuthorized(string username, string? password)
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

    public CertificateConfiguration CloneForSigning(ILogger<CertificateConfiguration> logger,
        IHardwareCertificateUnlocker unlocker)
    {
        var configuration = new CertificateConfiguration
        {
            Username = Username, Password = Password, LocalStore = LocalStore, Azure = Azure
        };

        if (LocalStore != null || Azure != null || SigningServer != null)
        {
            configuration.LoadCertificate(logger, unlocker);
        }
        else if(Certificate != null && PrivateKey != null)
        {
            // NOTE: This path is mainly needed for testing and rather not in production.
            configuration.Certificate = new X509Certificate2(Certificate);
            switch (PrivateKey)
            {
                case RSACng pk:
                    configuration.PrivateKey = new RSACng(pk.Key); 
                    break; 
                case DSACng pk:
                    configuration.PrivateKey = new DSACng(pk.Key);
                    break;
                case ECDsaCng pk:
                    configuration.PrivateKey = new ECDsaCng(pk.Key);
                    break;
                case RSACryptoServiceProvider pk:
                    var rsaCsp = new RSACryptoServiceProvider();
                    rsaCsp.ImportParameters(pk.ExportParameters(false));
                    configuration.PrivateKey = rsaCsp;
                    break;
                case DSACryptoServiceProvider pk:
                    var dsaCsp = new DSACryptoServiceProvider();
                    dsaCsp.ImportParameters(pk.ExportParameters(false));
                    configuration.PrivateKey = dsaCsp;
                    break;
                default:
                    throw new InvalidConfigurationException("Cannot clone private key");
            }
        }
        else
        {
            throw new InvalidConfigurationException("Cannot load certificate");
        }

        return configuration;
    }
}
