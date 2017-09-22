using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using NUnit.Framework;
using SigningServer.Client;
using SigningServer.Server;
using SigningServer.Server.Configuration;

namespace SigningServer.Test
{
    [TestFixture]
    public class SigningServerIntegrationTest : UnitTestBase
    {
        private CertificateStoreHelper _certificateHelper;
        private SigningServerService _service;
        [TestFixtureSetUp]
        public void Setup()
        {
            _certificateHelper = new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", StoreName.My,
                StoreLocation.LocalMachine);

            var configuration = new SigningServerConfiguration
            {
                Port = 47111,
                TimestampServer = ConfigurationManager.AppSettings["TimestampServer"],
                Certificates = new[]
                {
                    new CertificateConfiguration
                    {
                        Thumbprint = _certificateHelper.Certificate.Thumbprint,
                        StoreName = (StoreName) Enum.Parse(typeof (StoreName), _certificateHelper.Store.Name),
                        StoreLocation = _certificateHelper.Store.Location
                    }
                },
                WorkingDirectory = "WorkingDirectory"
            };
            File.WriteAllText("config.json", JsonConvert.SerializeObject(configuration));

            _service = new SigningServerService();
            _service.ConsoleStart();
        }

        [TestFixtureTearDown]
        public void TearDown()
        {
            _service.ConsoleStop();
        }

        [Test]
        [DeploymentItem("TestFiles", "IntegrationTestFiles")]
        public void ValidTestRun()
        {
            var client = new SigningClient(new SigningClientConfiguration
            {
                SigningServer = "localhost:47111"
            });
            client.SignFile("IntegrationTestFiles/unsigned");

            Assert.AreEqual(0, Directory.GetFiles("WorkingDirectory").Length, "Server Side file cleanup failed");

            var signedFiles = Directory.GetFiles("IntegrationTestFiles", "*.*", SearchOption.AllDirectories);
            var signingTools = _service.SigningServer.SigningToolProvider;

            foreach (var signedFile in signedFiles)
            {
                var tool = signingTools.GetSigningTool(signedFile);
                Assert.IsNotNull(tool, "Could not find signing tool for file {0}", signedFile);

                Assert.IsTrue(tool.IsFileSigned(signedFile), "File {0} was not signed", signedFile);
            }

        }

    }
}
