using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NLog;
using NLog.Config;
using SigningServer.Server.Configuration;

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
                Certificate.PrivateKey = CertificateConfiguration.PatchHashSupport(rsaCsp);
            }

            Log.Info("Certificate loaded");
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