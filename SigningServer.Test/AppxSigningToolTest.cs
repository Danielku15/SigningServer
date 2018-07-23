using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using SigningServer.Contracts;
using SigningServer.Server.Appx;

namespace SigningServer.Test
{
    [TestFixture]
    public class AppxSigningToolTest : UnitTestBase
    {
        [Test]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse()
        {
            using (var signingTool = new AppxSigningTool())
            {
                Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.appx"));
                Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.appx"));
            }
        }

        [Test]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            using (var signingTool = new AppxSigningTool())
            {
                Assert.IsTrue(File.Exists("TestFiles/signed/signed.appx"));
                Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.appx"));
            }
        }

        [Test]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                using (var signingTool = new AppxSigningTool())
                {
                    Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.appx"));
                    Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.appx"));
                }
            }
        }

        [Test]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue()
        {
            using (
              new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", StoreName.Root,
                  StoreLocation.LocalMachine))
            {
                using (var signingTool = new AppxSigningTool())
                {
                    Assert.IsTrue(File.Exists("TestFiles/signed/signed.appx"));
                    Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.appx"));
                }
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Works()
        {
            using (var signingTool = new AppxSigningTool())
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.appx", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "Unsigned_WrongPublishedFails")]
        public void SignFile_Unsigned_WrongPublishedFails()
        {
            using (var signingTool = new AppxSigningTool())
            {
                var fileName = "Unsigned_WrongPublishedFails/unsigned/UnsignedWrongPublisher.appx";
                var certificate = new X509Certificate2("Certificates/SigningServer.Test.pfx");
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
                Assert.IsInstanceOf<MemoryStream>(response.FileContent);
                Assert.AreEqual(response.FileSize, response.FileContent.Length);
                Assert.AreEqual(0, response.FileSize);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_NoResign_Fails()
        {
            using (var signingTool = new AppxSigningTool())
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.appx", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Resign_Fails()
        {
            using (var signingTool = new AppxSigningTool())
            {
                var fileName = "NoResign_Works/signed/signed.appx";
                var certificate = new X509Certificate2("Certificates/SigningServer.Test.pfx");
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
                Assert.IsTrue(signingTool.IsFileSigned(fileName));
                Assert.IsInstanceOf<MemoryStream>(response.FileContent);
                Assert.AreEqual(response.FileSize, response.FileContent.Length);
                Assert.AreEqual(0, response.FileSize);
            }
        }
    }
}
