using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NLog;

namespace SigningServer.Test
{
    [TestClass]
    public class AssemblyEvents
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();
        private static X509Certificate2 _certificate;
        
        [AssemblyInitialize]
        public static void AssemblyInit(TestContext context)
        {
            // attempt to import certificate once into the certificate store
            // otherwise it seems the CSP is not active on the system
            try
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);
                    _certificate = new X509Certificate2(UnitTestBase.CertificatePath, UnitTestBase.CertificatePassword);
                    store.Add(_certificate);
                    store.Close();
                }
            }
            catch (Exception e)
            {
                Log.Error(e, "Failed to import certificate to store");
            }
        }
        
        [AssemblyCleanup]
        public static void AssemblyCleanup()
        {
            try
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Remove(_certificate);
                    store.Close();
                }
            }
            catch (Exception e)
            {
                Log.Error(e, "Failed to cleanup certificate from store");
            }
        }
        
    }
}