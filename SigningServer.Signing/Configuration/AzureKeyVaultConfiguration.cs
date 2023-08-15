using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using RSAKeyVaultProvider;

namespace SigningServer.Signing.Configuration;

/// <summary>
/// Represents the configuration of a certificate loaded from an Azure KeyVault.
/// </summary>
public class AzureKeyVaultConfiguration
{
    /// <summary>
    /// The url to the azure keyvault like https://weu-000-keyvaultname.vault.azure.net/
    /// </summary>
    public string KeyVaultUrl { get; set; } = string.Empty;

    /// <summary>
    /// The ID of the tenant for accessing the keyvault
    /// </summary>
    public string? TenantId { get; set; }

    /// <summary>
    /// The name of the certificate in the key vault
    /// </summary>
    public string? CertificateName { get; set; }

    /// <summary>
    /// The client id for accessing the Key Vault (OAuth Client Credentias Grant flow)
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// The client secret for accessing the Key Vault (OAuth Client Credentias Grant flow)
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Whether to attempt using a managed identity for authentication
    /// </summary>
    public bool ManagedIdentity { get; set; }

    public async Task LoadAsync(ILogger logger, CertificateConfiguration certificateConfiguration)
    {
        logger.LogInformation("Loading Certificate from azure");
        var credentials = ManagedIdentity
            ? (TokenCredential)new DefaultAzureCredential()
            : new ClientSecretCredential(TenantId, ClientId, ClientSecret);

        var client = new CertificateClient(new Uri(KeyVaultUrl), credentials);
        var azureCertificate = (await client.GetCertificateAsync(CertificateName)).Value;
        var certificate = new X509Certificate2(azureCertificate.Cer);
        if (certificate.GetRSAPublicKey() is not null)
        {
            certificateConfiguration.PrivateKey = RSAFactory.Create(credentials, azureCertificate.KeyId, certificate);
        }
        else if (certificate.GetECDsaPublicKey() is not null)
        {
            certificateConfiguration.PrivateKey = ECDsaFactory.Create(credentials, azureCertificate.KeyId, certificate);
        }
        else
        {
            throw new InvalidConfigurationException("Unsupported certificate type: " + certificate.PublicKey.Oid);
        }

        certificateConfiguration.Certificate = certificate;
    }

    public override string ToString()
    {
        return $"Certificate={CertificateName}";
    }
}
