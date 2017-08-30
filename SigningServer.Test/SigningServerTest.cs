using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Moq;
using NUnit.Framework;
using SigningServer.Contracts;
using SigningServer.Server.Configuration;

namespace SigningServer.Test
{
    [TestFixture]
    public class SigningServerTest : UnitTestBase
    {
        private ISigningToolProvider CreateEmptySigningToolProvider()
        {
            var mockedSigningToolProvider = new Mock<ISigningToolProvider>();
            mockedSigningToolProvider.Setup(m => m.SupportedFileExtensions).Returns(new string[0]);
            mockedSigningToolProvider.Setup(m => m.SupportedHashAlgorithms).Returns(new string[0]);
            mockedSigningToolProvider.Setup(m => m.GetSigningTool(It.IsAny<string>())).Returns((ISigningTool)null);
            return mockedSigningToolProvider.Object;
        }

        [Test]
        [ExpectedException(typeof(InvalidConfigurationException), ExpectedMessage = InvalidConfigurationException.NoValidCertificatesMessage)]
        public void TestNoCertificatesThrowsError()
        {
            var emptyConfig = new SigningServerConfiguration();
            var server = new Server.SigningServer(emptyConfig, CreateEmptySigningToolProvider());
        }

        [Test]
        [ExpectedException(typeof(InvalidConfigurationException), ExpectedMessage = InvalidConfigurationException.CreateWorkingDirectoryFailedMessage)]
        public void InvalidWorkingDirectoryThrowsError()
        {
            var emptyConfig = new SigningServerConfiguration
            {
                Certificates = new[]
                {
                    new CertificateConfiguration
                    {
                        Certificate = new X509Certificate2("Certificates/SigningServer.Test.pfx")
                    }
                },
                WorkingDirectory = "T:\\NotExisting"
            };
            var server = new Server.SigningServer(emptyConfig, CreateEmptySigningToolProvider());
            server.GetSupportedFileExtensions();
        }

        [Test]
        public void RelativeWorkingDirectoryGetsCreated()
        {
            var config = new SigningServerConfiguration
            {
                Certificates = new[]
                {
                    new CertificateConfiguration
                    {
                        Certificate = new X509Certificate2("Certificates/SigningServer.Test.pfx")
                    }
                },
                WorkingDirectory = "WorkingDirectory"
            };
            var server = new Server.SigningServer(config, CreateEmptySigningToolProvider());
            Assert.IsTrue(Directory.Exists(Path.Combine(Environment.CurrentDirectory, config.WorkingDirectory)));
            Directory.Delete(Path.Combine(Environment.CurrentDirectory, config.WorkingDirectory), true);
        }

        [Test]
        public void RelativeWorkingDirectoryGetsCleaned()
        {
            var config = new SigningServerConfiguration
            {
                Certificates = new[]
                {
                    new CertificateConfiguration
                    {
                        Certificate = new X509Certificate2("Certificates/SigningServer.Test.pfx")
                    }
                },
                WorkingDirectory = "WorkingDirectory"
            };

            Directory.CreateDirectory("WorkingDirectory");
            File.WriteAllText("WorkingDirectory/test.txt", "test");

            var server = new Server.SigningServer(config, CreateEmptySigningToolProvider());
            Assert.IsTrue(Directory.Exists(Path.Combine(Environment.CurrentDirectory, config.WorkingDirectory)));

            Assert.AreEqual(0, Directory.GetFiles("WorkingDirectory").Length);
            Directory.Delete(Path.Combine(Environment.CurrentDirectory, config.WorkingDirectory), true);
        }

        [Test]
        public void AbsoluteWorkingDirectoryGetsCreated()
        {
            var temp = Path.Combine(Path.GetTempPath(), "WorkingDirectory");
            var config = new SigningServerConfiguration
            {
                Certificates = new[]
                {
                    new CertificateConfiguration
                    {
                        Certificate = new X509Certificate2("Certificates/SigningServer.Test.pfx")
                    }
                },
                WorkingDirectory = temp
            };
            var server = new Server.SigningServer(config, CreateEmptySigningToolProvider());
            Assert.IsTrue(Directory.Exists(temp));
            Directory.Delete(temp, true);
        }

        [Test]
        public void LoadCertificateFromStoreWorks()
        {
            using (var cert = new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", StoreName.My,
                    StoreLocation.LocalMachine))
            {
                var emptyConfig = new SigningServerConfiguration
                {
                    Certificates = new[]
                    {
                        new CertificateConfiguration
                        {
                            Thumbprint = cert.Certificate.Thumbprint,
                            StoreName = (StoreName) Enum.Parse(typeof(StoreName), cert.Store.Name),
                            StoreLocation = cert.Store.Location,
                        }
                    },
                    WorkingDirectory = "WorkingDirectory"
                };
                var server = new Server.SigningServer(emptyConfig, CreateEmptySigningToolProvider());
                Assert.AreEqual(1, server.Configuration.Certificates.Length);
                Assert.AreEqual(emptyConfig.Certificates[0].Thumbprint, server.Configuration.Certificates[0].Certificate.Thumbprint);
            }
        }
    }
}
