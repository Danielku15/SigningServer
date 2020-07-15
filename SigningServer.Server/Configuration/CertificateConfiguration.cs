using System;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

        [JsonIgnore]
        public X509Certificate2 Certificate { get; set; }

        [JsonIgnore]
        public bool IsAnonymous => string.IsNullOrWhiteSpace(Username);

        public CertificateConfiguration()
        {
        }

        public CertificateConfiguration(CertificateConfiguration other)
        {
            Username = other.Username;
            Password = other.Password;
            StoreName = other.StoreName;
            StoreLocation = other.StoreLocation;
            Thumbprint = other.Thumbprint;
            Certificate = other.Certificate;
        }

        public void LoadCertificate()
        {
            using (var store = new X509Store(StoreName, StoreLocation))
            {
                store.Open(OpenFlags.ReadOnly);

                var certificates =
                    store.Certificates.OfType<X509Certificate2>()
                        .Where(c => c.Thumbprint.Equals(Thumbprint, StringComparison.InvariantCultureIgnoreCase)).ToArray();
                if (certificates.Length == 0)
                {
                    throw new CertificateNotFoundException($"No certificate with the thumbprint '{Thumbprint}' found");
                }

                Certificate = certificates.FirstOrDefault(c => c.HasPrivateKey);
                if (Certificate == null)
                {
                    throw new CertificateNotFoundException($"Certificate with thumbprint '{Thumbprint}' has no private key");
                }


                // For SmartCards/Hardware dongles we create a new RSACryptoServiceProvider with the corresponding pin
                var rsa = (RSACryptoServiceProvider)Certificate.PrivateKey;
                if (rsa.CspKeyContainerInfo.HardwareDevice)
                {
                    var keyPassword = new SecureString();
                    var decrypted = DataProtector.UnprotectData(TokenPin);
                    foreach (var c in decrypted)
                    {
                        keyPassword.AppendChar(c);
                    }
                    var csp = new CspParameters(1 /*RSA*/,
                                        rsa.CspKeyContainerInfo.ProviderName,
                                        rsa.CspKeyContainerInfo.KeyContainerName,
                                        new System.Security.AccessControl.CryptoKeySecurity(),
                                        keyPassword);
                    Certificate = new X509Certificate2(Certificate.RawData)
                    {
                        PrivateKey = new RSACryptoServiceProvider(csp)
                    };
                }

            }
        }

        public bool IsAuthorized(string username, string password)
        {
            return string.Equals(Username, username, StringComparison.CurrentCultureIgnoreCase) && Password == password;
        }
    }
}