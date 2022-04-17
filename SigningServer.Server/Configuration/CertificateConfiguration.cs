using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using NLog;
using RSAKeyVaultProvider;

namespace SigningServer.Server.Configuration;

public class CertificateConfiguration
{
    private static readonly Logger Log = LogManager.GetCurrentClassLogger();
    public string Username { get; set; }
    public string Password { get; set; }

    public string Thumbprint { get; set; }


    // Local Certificate
    [JsonConverter(typeof(StringEnumConverter))]
    public StoreName StoreName { get; set; }

    [JsonConverter(typeof(StringEnumConverter))]
    public StoreLocation StoreLocation { get; set; }

    public string TokenPin { get; set; }

    public AzureKeyVaultConfiguration Azure { get; set; }

    [JsonIgnore] public X509Certificate2 Certificate { get; set; }
    [JsonIgnore] public AsymmetricAlgorithm PrivateKey { get; set; }

    [JsonIgnore] public bool IsAnonymous => string.IsNullOrWhiteSpace(Username);

    public void LoadCertificate(HardwareCertificateUnlocker unlocker)
    {
        // only do reloads if cert needs hardware unlock or certificate is not loaded at all
        if (string.IsNullOrEmpty(TokenPin) && Certificate != null)
        {
            return;
        }

        Certificate?.Dispose();

        if (!string.IsNullOrEmpty(Azure?.KeyVaultUrl))
        {
            LoadCertificateFromAzure();
        }
        else
        {
            LoadCertificateFromLocalMachine(unlocker);
        }
    }

    private void LoadCertificateFromAzure()
    {
        Log.Info("Loading Certificate from azure");
        var credentials = Azure.ManagedIdentity
            ? (TokenCredential)new DefaultAzureCredential()
            : new ClientSecretCredential(Azure.TenantId, Azure.ClientId, Azure.ClientSecret);

        var client = new CertificateClient(new Uri(Azure.KeyVaultUrl), credentials);
        var azureCertificate = client.GetCertificate(Azure.CertificateName).Value;
        var certificate = new X509Certificate2(azureCertificate.Cer);
        PrivateKey = RSAFactory.Create(credentials, azureCertificate.KeyId, certificate);
        Certificate = certificate;
    }

    private void LoadCertificateFromLocalMachine(HardwareCertificateUnlocker unlocker)
    {
        Log.Info("Loading Certificate from local machine");
        using var store = new X509Store(StoreName, StoreLocation);
        store.Open(OpenFlags.ReadOnly);

        var certificates =
            store.Certificates
                .Where(c => Thumbprint.Equals(c.Thumbprint, StringComparison.InvariantCultureIgnoreCase))
                .ToArray();
        if (certificates.Length == 0)
        {
            throw new CertificateNotFoundException($"No certificate with the thumbprint '{Thumbprint}' found");
        }

        var certificate = certificates.FirstOrDefault(c => c.HasPrivateKey);

        Certificate = certificate ?? throw new CertificateNotFoundException(
            $"Certificate with thumbprint '{Thumbprint}' has no private key");

        PrivateKey = certificate.GetECDsaPrivateKey() ??
                     certificate.GetRSAPrivateKey() ??
                     (AsymmetricAlgorithm)certificate.GetDSAPrivateKey();

        var rsa = Certificate.GetRSAPrivateKey();
        switch (rsa)
        {
            // For SmartCards/Hardware dongles we create a new RSACryptoServiceProvider with the corresponding pin
            case RSACryptoServiceProvider rsaCsp when !string.IsNullOrEmpty(TokenPin):
                {
                    Log.Info("Patching RsaCsp for Hardware Token with pin");
                    var keyPassword = new SecureString();
                    var decrypted = DataProtector.UnprotectData(TokenPin);
                    foreach (var c in decrypted)
                    {
                        keyPassword.AppendChar(c);
                    }

                    var csp = new CspParameters(1 /*RSA*/,
                        rsaCsp.CspKeyContainerInfo.ProviderName,
                        rsaCsp.CspKeyContainerInfo.KeyContainerName) { KeyPassword = keyPassword };
                    csp.Flags |= CspProviderFlags.NoPrompt;

                    PrivateKey = new RSACryptoServiceProvider(csp);
                    unlocker?.RegisterForUpdate(this);
                    break;
                }
            // For normal Certs we patch the Hash Support if needed.
            case RSACryptoServiceProvider rsaCsp:
                {
                    PrivateKey = PatchHashSupport(rsaCsp);
                    break;
                }
            case RSACng cng when !string.IsNullOrEmpty(TokenPin):
                {
                    var decrypted = DataProtector.UnprotectData(TokenPin);
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
                    // ReSharper disable once InconsistentNaming Win32 constant
                    const string NCRYPT_PIN_PROPERTY = "SmartCardPin";

                    // get bytes with null terminator
                    var propertyBytes = new byte[Encoding.Unicode.GetByteCount(decrypted) + 2];
                    Encoding.Unicode.GetBytes(decrypted, 0, decrypted.Length, propertyBytes, 0);
                    cng.Key.SetProperty(new CngProperty(
                        NCRYPT_PIN_PROPERTY,
                        propertyBytes,
                        CngPropertyOptions.None
                    ));
                    break;
                }
        }
    }

    public bool IsAuthorized(string username, string password)
    {
        return string.Equals(Username, username, StringComparison.CurrentCultureIgnoreCase) && Password == password;
    }

    public static RSACryptoServiceProvider PatchHashSupport(RSACryptoServiceProvider orgKey)
    {
        var newKey = orgKey;
        try
        {
            // ReSharper disable once InconsistentNaming Win32 constant
            const int PROV_RSA_AES = 24; // CryptoApi provider type for an RSA provider supporting sha-256 digital signatures

            // ProviderType == 1(PROV_RSA_FULL) and providerType == 12(PROV_RSA_SCHANNEL) are provider types that only support SHA1.
            // Change them to PROV_RSA_AES=24 that supports SHA2 also. Only levels up if the associated key is not a hardware key.
            // Another provider type related to rsa, PROV_RSA_SIG == 2 that only supports Sha1 is no longer supported
            if (orgKey.CspKeyContainerInfo.ProviderType is 1 or 12 && !orgKey.CspKeyContainerInfo.HardwareDevice)
            {
                Log.Info("Patching RsaCsp for Hash Support");

                var csp = new CspParameters
                {
                    ProviderType = PROV_RSA_AES,
                    KeyContainerName = orgKey.CspKeyContainerInfo.KeyContainerName,
                    KeyNumber = (int)orgKey.CspKeyContainerInfo.KeyNumber
                };

                if (orgKey.CspKeyContainerInfo.MachineKeyStore)
                {
                    csp.Flags = CspProviderFlags.UseMachineKeyStore;
                }

                //
                // If UseExistingKey is not specified, the CLR will generate a key for a non-existent group.
                // With this flag, a CryptographicException is thrown instead.
                //
                csp.Flags |= CspProviderFlags.UseExistingKey;
                return new RSACryptoServiceProvider(csp);
            }
            else
            {
                Log.Info("Skipping RsaCsp Patching ");
            }
        }
        finally
        {
            if (!ReferenceEquals(orgKey, newKey))
            {
                orgKey.Dispose();
            }
        }

        return newKey;
    }
}
