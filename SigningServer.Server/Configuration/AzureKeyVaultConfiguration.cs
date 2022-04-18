using System;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using RSAKeyVaultProvider;

namespace SigningServer.Server.Configuration;

/// <summary>
/// Represents the configuration of a certificate loaded from an Azure KeyVault.
/// </summary>
public class AzureKeyVaultConfiguration
{
    /// <summary>
    /// The url to the azure keyvault like https://weu-000-keyvaultname.vault.azure.net/
    /// </summary>
    public string KeyVaultUrl { get; set; }
    /// <summary>
    /// The ID of the tenant for accessing the keyvault
    /// </summary>
    public string TenantId { get; set; }

    /// <summary>
    /// The name of the certificate in the key vault
    /// </summary>
    public string CertificateName { get; set; }
        
    /// <summary>
    /// The client id for accessing the Key Vault (OAuth Client Credentias Grant flow)
    /// </summary>
    public string ClientId { get; set; }
    
    /// <summary>
    /// The client secret for accessing the Key Vault (OAuth Client Credentias Grant flow)
    /// </summary>
    public string ClientSecret { get; set; }
        
    /// <summary>
    /// Whether to attempt using a managed identity for authentication
    /// </summary>
    public bool ManagedIdentity { get; set; }

    public void Load(ILogger logger, CertificateConfiguration certificateConfiguration)
    {
        logger.LogInformation("Loading Certificate from azure");
        var credentials = ManagedIdentity
            ? (TokenCredential)new DefaultAzureCredential()
            : new ClientSecretCredential(TenantId, ClientId, ClientSecret);

        var client = new CertificateClient(new Uri(KeyVaultUrl), credentials);
        var azureCertificate = client.GetCertificate(CertificateName).Value;
        var certificate = new X509Certificate2(azureCertificate.Cer);
        certificateConfiguration.PrivateKey = RSAFactory.Create(credentials, azureCertificate.KeyId, certificate);
        certificateConfiguration.Certificate = certificate;
    }

    public override string ToString()
    {
        return $"Certificate={CertificateName}";
    }
}
