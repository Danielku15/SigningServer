namespace SigningServer.Server.Configuration;

public class AzureKeyVaultConfiguration
{
    public string KeyVaultUrl { get; set; }
    public string TenantId { get; set; }

    public string CertificateName { get; set; }
        
    // For OAuth Client Credentials Grant Flow
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
        
    // For Managed Identity Authentication
    public bool ManagedIdentity { get; set; }
}