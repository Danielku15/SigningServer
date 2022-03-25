using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Contracts;
using SigningServer.Server.SigningTool;

namespace SigningServer.Test
{
    [TestClass]
    public class AppxSigningToolTest : UnitTestBase
    {
        [TestMethod]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse()
        {
            var signingTool = new AppxSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.appx"));
            Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.appx"));
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            var signingTool = new AppxSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/signed/signed.appx"));
            Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.appx"));
        }

        [TestMethod]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new AppxSigningTool();
                Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.appx"));
                Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.appx"));
            }
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue()
        {
            using (
              new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                  StoreLocation.LocalMachine))
            {
                var signingTool = new AppxSigningTool();
                Assert.IsTrue(File.Exists("TestFiles/signed/signed.appx"));
                Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.appx"));
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Works()
        {
            var signingTool = new AppxSigningTool();
            CanSign(signingTool, "SignFile_Works/unsigned/unsigned.appx", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Unsigned_WrongPublishedFails")]
        public void SignFile_Unsigned_WrongPublishedFails()
        {
            var signingTool = new AppxSigningTool();
            var fileName = "Unsigned_WrongPublishedFails/error/UnsignedWrongPublisher.appx";
            var certificate = new X509Certificate2("Certificates/SigningServer.Test.pfx", CertificatePassword);
            Assert.IsTrue(signingTool.IsFileSupported(fileName));
            var response = new SignFileResponse();
            var request = new SignFileRequest
            {
                FileName = fileName,
                OverwriteSignature = true
            };
            signingTool.SignFile(fileName, certificate, ConfigurationManager.AppSettings["TimestampServer"], request, response);
            Trace.WriteLine(response);
            Assert.AreEqual(SignFileResponseResult.FileNotSignedError, response.Result);
            Assert.IsFalse(signingTool.IsFileSigned(fileName));
            Assert.IsInstanceOfType(response.FileContent, typeof(MemoryStream));
            Assert.AreEqual(response.FileSize, response.FileContent.Length);
            Assert.AreEqual(0, response.FileSize);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_NoResign_Fails()
        {
            var signingTool = new AppxSigningTool();
            CannotResign(signingTool, "NoResign_Fails/signed/signed.appx", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Resign_Works()
        {
            var signingTool = new AppxSigningTool();
            var fileName = "NoResign_Works/signed/signed.appx";
            var certificate = new X509Certificate2("Certificates/SigningServer.Test.pfx", CertificatePassword);
            Assert.IsTrue(signingTool.IsFileSupported(fileName));
            var response = new SignFileResponse();
            var request = new SignFileRequest
            {
                FileName = fileName,
                OverwriteSignature = true
            };
            signingTool.SignFile(fileName, certificate, ConfigurationManager.AppSettings["TimestampServer"], request, response);
            Trace.WriteLine(response);
            Assert.AreEqual(SignFileResponseResult.FileResigned, response.Result);
            Assert.IsTrue(signingTool.IsFileSigned(fileName));
            Assert.IsInstanceOfType(response.FileContent, typeof(FileStream));
        }
    }
}
