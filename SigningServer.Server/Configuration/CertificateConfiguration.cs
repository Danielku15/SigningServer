using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using SigningServer.Server.SigningTool;

namespace SigningServer.Server.Configuration
{
    public class CertificateConfiguration
    {
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
            var credentials = Azure.ManagedIdentity
                ? (TokenCredential)new DefaultAzureCredential()
                : new ClientSecretCredential(Azure.TenantId, Azure.ClientId, Azure.ClientSecret);

            var client = new CertificateClient(new Uri(Azure.KeyVaultUrl), credentials);
            var azureCertificate = client.GetCertificate(Azure.CertificateName).Value;
            var certificate = new AzureX509Certificate2(azureCertificate.Cer);
            certificate.SetAzurePrivateKey(credentials, azureCertificate.KeyId);

            Certificate = certificate;
        }

        private void LoadCertificateFromLocalMachine(HardwareCertificateUnlocker unlocker)
        {
            using (var store = new X509Store(StoreName, StoreLocation))
            {
                store.Open(OpenFlags.ReadOnly);

                var certificates =
                    store.Certificates.OfType<X509Certificate2>()
                        .Where(c => Thumbprint.Equals(c.Thumbprint, StringComparison.InvariantCultureIgnoreCase))
                        .ToArray();
                if (certificates.Length == 0)
                {
                    throw new CertificateNotFoundException($"No certificate with the thumbprint '{Thumbprint}' found");
                }

                var certificate = certificates.FirstOrDefault(c => c.HasPrivateKey);
                if (certificate == null)
                {
                    throw new CertificateNotFoundException(
                        $"Certificate with thumbprint '{Thumbprint}' has no private key");
                }

                // TODO: check Hash Support 
                // For SmartCards/Hardware dongles we create a new RSACryptoServiceProvider with the corresponding pin
                // TODO: Cng support
                if (!string.IsNullOrEmpty(TokenPin)
                    && certificate.PrivateKey is RSACryptoServiceProvider rsaCsp
                    && rsaCsp.CspKeyContainerInfo.HardwareDevice)
                {
                    var keyPassword = new SecureString();
                    var decrypted = DataProtector.UnprotectData(TokenPin);
                    foreach (var c in decrypted)
                    {
                        keyPassword.AppendChar(c);
                    }

                    var csp = new CspParameters(1 /*RSA*/,
                        rsaCsp.CspKeyContainerInfo.ProviderName,
                        rsaCsp.CspKeyContainerInfo.KeyContainerName,
                        new System.Security.AccessControl.CryptoKeySecurity(),
                        keyPassword);
                    var oldCert = certificate;
                    certificate = new X509Certificate2(oldCert.RawData)
                    {
                        PrivateKey = new RSACryptoServiceProvider(csp)
                    };
                    oldCert.Dispose();
                    unlocker?.RegisterForUpdate(this);
                }

                Certificate = certificate;
            }
        }

        public bool IsAuthorized(string username, string password)
        {
            return string.Equals(Username, username, StringComparison.CurrentCultureIgnoreCase) && Password == password;
        }
    }
}