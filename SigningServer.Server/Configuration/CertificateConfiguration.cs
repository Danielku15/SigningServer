using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace SigningServer.Server.Configuration
{
    public class CertificateConfiguration
    {
        public string Username { get; set; }
        public string Password { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public StoreName StoreName { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public StoreLocation StoreLocation { get; set; }

        public string Thumbprint { get; set; }
        public string TokenPin { get; set; }

        [JsonIgnore] public X509Certificate2 Certificate { get; set; }

        [JsonIgnore] public bool IsAnonymous => string.IsNullOrWhiteSpace(Username);

        public void LoadCertificate(HardwareCertificateUnlocker unlocker)
        {
            Certificate?.Dispose();

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

                Certificate = certificates.FirstOrDefault(c => c.HasPrivateKey);
                if (Certificate == null)
                {
                    throw new CertificateNotFoundException(
                        $"Certificate with thumbprint '{Thumbprint}' has no private key");
                }


                // For SmartCards/Hardware dongles we create a new RSACryptoServiceProvider with the corresponding pin
                if (!string.IsNullOrEmpty(TokenPin)
                    && Certificate.PrivateKey is RSACryptoServiceProvider rsaCsp
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
                    var oldCert = Certificate;
                    Certificate = new X509Certificate2(oldCert.RawData)
                    {
                        PrivateKey = new RSACryptoServiceProvider(csp)
                    };
                    oldCert.Dispose();
                    unlocker?.RegisterForUpdate(this);
                }
            }
        }

        public bool IsAuthorized(string username, string password)
        {
            return string.Equals(Username, username, StringComparison.CurrentCultureIgnoreCase) && Password == password;
        }
    }
}