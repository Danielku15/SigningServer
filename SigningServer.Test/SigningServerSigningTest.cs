using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Moq;
using NUnit.Framework;
using SigningServer.Contracts;
using SigningServer.Server;
using SigningServer.Server.Configuration;
using SigningServer.Server.SigningTool;

namespace SigningServer.Test
{
    [TestFixture]
    public class SigningServerSigningTest : UnitTestBase
    {
        private CertificateStoreHelper _certificateHelper;
        private SigningServerConfiguration _configuration;
        private ISigningToolProvider _emptySigningToolProvider;
        private ISigningToolProvider _simultateSigningToolProvider;

        [TestFixtureSetUp]
        public void Setup()
        {
            _certificateHelper = new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", StoreName.My,
                StoreLocation.LocalMachine);

            _configuration = new SigningServerConfiguration
            {
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

            _emptySigningToolProvider = new EnumerableSigningToolProvider(Enumerable.Empty<ISigningTool>());

            var simulateSigningTool = new Mock<ISigningTool>();
            simulateSigningTool.Setup(t => t.GetSupportedFileExtensions()).Returns(new[] { "*" });
            simulateSigningTool.Setup(t => t.IsFileSigned(It.IsAny<string>())).Returns(true);
            simulateSigningTool.Setup(t => t.IsFileSupported(It.IsAny<string>())).Returns(true);
            simulateSigningTool.Setup(t => t.SignFile(It.IsAny<string>(), It.IsAny<X509Certificate2>(), It.IsAny<string>(), It.IsAny<SignFileRequest>(), It.IsAny<SignFileResponse>())).Callback(
                (string file, X509Certificate2 cert, string timestampserver, SignFileRequest request, SignFileResponse response) =>
                {
                    response.Result = SignFileResponseResult.FileSigned;
                    var fs = new FileStream(file, FileMode.Open, FileAccess.Read);
                    response.FileContent = fs;
                    response.FileSize = fs.Length;
                });

            _simultateSigningToolProvider = new EnumerableSigningToolProvider(new[] { simulateSigningTool.Object });
        }

        [TestFixtureTearDown]
        public void TearDown()
        {
            _certificateHelper.Dispose();
        }

        [Test]
        public void SignFile_EmptyFile_Fails()
        {
            var server = new Server.SigningServer(_configuration, _emptySigningToolProvider);

            var request = new SignFileRequest
            {
                FileSize = 0,
                FileContent = null
            };
            var response = server.SignFile(request);
            Assert.AreEqual(SignFileResponseResult.FileNotSignedError, response.Result);

            request = new SignFileRequest
            {
                FileSize = 100,
                FileContent = null
            };
            response = server.SignFile(request);
            Assert.AreEqual(SignFileResponseResult.FileNotSignedError, response.Result);

            request = new SignFileRequest
            {
                FileSize = 0,
                FileContent = new MemoryStream()
            };
            response = server.SignFile(request);
            Assert.AreEqual(SignFileResponseResult.FileNotSignedError, response.Result);
        }

        [Test]
        public void SignFile_NoAnonymousSigning_Fails()
        {
            var configuration = new SigningServerConfiguration
            {
                Certificates = new[]
                {
                    new CertificateConfiguration
                    {
                        Username = "SignUser",
                        Password = "SignPass",
                        Thumbprint = _certificateHelper.Certificate.Thumbprint,
                        StoreName = (StoreName) Enum.Parse(typeof (StoreName), _certificateHelper.Store.Name),
                        StoreLocation = _certificateHelper.Store.Location
                    }
                },
                WorkingDirectory = "WorkingDirectory"
            };

            var server = new Server.SigningServer(configuration, _emptySigningToolProvider);

            var testData = new MemoryStream(File.ReadAllBytes("TestFiles/unsigned/unsigned.exe"));
            var request = new SignFileRequest
            {
                FileName = "unsigned.exe",
                FileSize = testData.Length,
                FileContent = testData
            };

            var response = server.SignFile(request);
            Assert.AreEqual(SignFileResponseResult.FileNotSignedUnauthorized, response.Result);
        }

        [Test]
        public void SignFile_UnsupportedFormat_Fails()
        {
            var server = new Server.SigningServer(_configuration, _emptySigningToolProvider);

            var testData = new MemoryStream(File.ReadAllBytes("TestFiles/unsigned/unsigned.exe"));
            var request = new SignFileRequest
            {
                FileName = "unsigned.exe",
                FileSize = testData.Length,
                FileContent = testData
            };

            var response = server.SignFile(request);
            Assert.AreEqual(SignFileResponseResult.FileNotSignedUnsupportedFormat, response.Result);
        }

        [Test]
        public void SignFile_UploadsFileToWorkingDirectory()
        {
            var server = new Server.SigningServer(_configuration, _simultateSigningToolProvider);

            var testData = new MemoryStream(File.ReadAllBytes("TestFiles/unsigned/unsigned.exe"));
            var request = new SignFileRequest
            {
                FileName = "unsigned.exe",
                FileSize = testData.Length,
                FileContent = testData
            };

            var response = server.SignFile(request);
            Assert.AreEqual(SignFileResponseResult.FileSigned, response.Result);
            var files = Directory.GetFileSystemEntries(_configuration.WorkingDirectory).ToArray();
            Assert.AreEqual(1, files.Length);
            response.Dispose();
        }

        [Test]
        public void SignFile_ResponseDisposeCleansFile()
        {
            var server = new Server.SigningServer(_configuration, _simultateSigningToolProvider);

            var testData = new MemoryStream(File.ReadAllBytes("TestFiles/unsigned/unsigned.exe"));
            var request = new SignFileRequest
            {
                FileName = "unsigned.exe",
                FileSize = testData.Length,
                FileContent = testData
            };

            var response = server.SignFile(request);
            Assert.AreEqual(SignFileResponseResult.FileSigned, response.Result);

            var files = Directory.GetFileSystemEntries(_configuration.WorkingDirectory).ToArray();
            Assert.AreEqual(1, files.Length);

            response.Dispose();

            files = Directory.GetFileSystemEntries(_configuration.WorkingDirectory).ToArray();
            Assert.AreEqual(0, files.Length);
        }
    }
}
