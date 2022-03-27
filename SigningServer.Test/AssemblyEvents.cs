using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NLog;

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
            // attempt to import certificate once into the certificate store
            // otherwise it seems the CSP is not active on the system
            try
            {
                Log.Info("Installing Certificate for testing to store");
                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);
                    var certificatePath = Path.Combine(UnitTestBase.ExecutionDirectory, "Certificates",
                        "SigningServer.Test.pfx");
                    var certificatePassword = "SigningServer";
                    Certificate = new X509Certificate2(certificatePath, certificatePassword);
                    PatchHashSupport(Certificate);
                    store.Add(Certificate);
                    store.Close();
                }

                Log.Info("Certificate installed");
            }
            catch (Exception e)
            {
                Log.Error(e, "Failed to import certificate to store");
            }
        }

        private static void PatchHashSupport(X509Certificate2 certificate)
        {
            if (certificate.PrivateKey is RSACryptoServiceProvider orgKey)
            {
                try
                {
                    const int
                        PROV_RSA_AES =
                            24; // CryptoApi provider type for an RSA provider supporting sha-256 digital signatures

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
                        certificate.PrivateKey = new RSACryptoServiceProvider(csp);
                    }
                }
                finally
                {
                    if (!ReferenceEquals(orgKey, certificate.PrivateKey))
                    {
                        orgKey.Dispose();
                    }
                }
            }
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