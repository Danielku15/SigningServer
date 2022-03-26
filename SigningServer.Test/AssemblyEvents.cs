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
                    var certificate = new X509Certificate2(UnitTestBase.CertificatePath, UnitTestBase.CertificatePassword);
                    store.Add(certificate);
                    store.Remove(certificate);
                }
            }
            catch (Exception e)
            {
                Log.Error(e, "Failed to import certificate to store");
            }
        }
        
    }
}