using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NLog;
using NLog.Config;

namespace SigningServer.Test
{
    [TestClass]
    public class AssemblyEvents
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();
        internal static X509Certificate2 Certificate;

        [AssemblyInitialize]
        public static void AssemblyInit(TestContext context)
        {
            // Enforce certificate.PrivateKey raw access, GetRSAPrivateKey would clone it but for azure certs we cannot clone the CSP params into a new RSACryptoServiceProvider
            AppContext.SetSwitch("Switch.System.Security.Cryptography.X509Certificates.RSACertificateExtensions.DontReliablyClonePrivateKey", true);

            LogManager.Configuration = new XmlLoggingConfiguration("NLog.config");

            var certificatePath = Path.Combine(UnitTestBase.ExecutionDirectory, "Certificates",
                "SigningServer.Test.pfx");
            var certificatePassword = "SigningServer";
            
            Log.Info("Loading certificate");

            Certificate = new X509Certificate2(certificatePath, certificatePassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.PersistKeySet);
            if (Certificate.PrivateKey is RSACryptoServiceProvider rsaCsp)
            {
                Certificate.PrivateKey = PatchHashSupport(rsaCsp);
            }

            Log.Info("Certificate loaded");
        }

        private static RSACryptoServiceProvider PatchHashSupport(RSACryptoServiceProvider orgKey)
        {
            var newKey = orgKey;
            try
            {
                const int PROV_RSA_AES = 24; // CryptoApi provider type for an RSA provider supporting sha-256 digital signatures

                // ProviderType == 1(PROV_RSA_FULL) and providerType == 12(PROV_RSA_SCHANNEL) are provider types that only support SHA1.
                // Change them to PROV_RSA_AES=24 that supports SHA2 also. Only levels up if the associated key is not a hardware key.
                // Another provider type related to rsa, PROV_RSA_SIG == 2 that only supports Sha1 is no longer supported
                if ((orgKey.CspKeyContainerInfo.ProviderType == 1 ||
                     orgKey.CspKeyContainerInfo.ProviderType == 12) && !orgKey.CspKeyContainerInfo.HardwareDevice)
                {
                    CspParameters csp = new CspParameters
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

        [AssemblyCleanup]
        public static void AssemblyCleanup()
        {
            try
            {
                Log.Info("Removeing test certificate from store");
                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Remove(Certificate);
                    store.Close();
                    Log.Info("Certificate removed");
                }
            }
            catch (Exception e)
            {
                Log.Error(e, "Failed to cleanup certificate from store");
            }
        }
    }
}