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
            //if (!string.IsNullOrEmpty(TokenCryptoProvider))
            //{
            //    // eToken Base Cryptographic Provider

            //    // we keep the token unlocked for the lifetime of the process
            //    // hence we do not release the handle via CryptReleaseContext
            //    UnlockToken();
            //}

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
                    var csp = new CspParameters(1 /*RSA*/,
                                        rsa.CspKeyContainerInfo.ProviderName,
                                        rsa.CspKeyContainerInfo.KeyContainerName,
                                        new System.Security.AccessControl.CryptoKeySecurity(),
                                        GetSecurePin());
                    var rsaCsp = new RSACryptoServiceProvider(csp);
                    Certificate.PrivateKey = rsaCsp;
                }

            }
        }
        private SecureString GetSecurePin()
        {
            var pwd = new SecureString();
            foreach (var c in TokenPin)
            {
                pwd.AppendChar(c);
            }
            return pwd;
        }


        //private void UnlockToken()
        //{
        //    IntPtr cryptProv = IntPtr.Zero;
        //    if (!CryptAcquireContext(ref cryptProv, TokenContainerName, TokenCryptoProvider, PROV_RSA_FULL, CRYPT_SILENT))
        //    {
        //        throw new InvalidConfigurationException($"Could not unlock token, could not acquire contet {Marshal.GetLastWin32Error():X}");
        //    }

        //    var bytes = Encoding.ASCII.GetBytes(TokenPin);

        //    if (!CryptSetProvParam(cryptProv, PP_SIGNATURE_PIN, bytes, 0))
        //    {
        //        throw new InvalidConfigurationException($"Could not unlock token, could not set provider param {Marshal.GetLastWin32Error():X}");
        //    }
        //}

        //private const int PROV_RSA_FULL = 1;
        //private const uint CRYPT_SILENT = 0x40;
        //private const uint PP_SIGNATURE_PIN = 0x21;

        //[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //private static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        //[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //private static extern bool CryptSetProvParam(IntPtr hProv, uint dwParam, [In] byte[] pbData, uint dwFlags);

        public bool IsAuthorized(string username, string password)
        {
            return string.Equals(Username, username, StringComparison.CurrentCultureIgnoreCase) && Password == password;
        }
    }
}