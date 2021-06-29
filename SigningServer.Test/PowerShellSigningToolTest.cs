using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Server.SigningTool;

namespace SigningServer.Test
{
    [TestClass]
    public class PowerShellSigningToolTest : UnitTestBase
    {
        [TestMethod]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse()
        {
            var signingTool = new PowerShellSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.ps1"));
            Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.ps1"));
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            var signingTool = new PowerShellSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/signed/signed.ps1"));
            Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.ps1"));
        }

        [TestMethod]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new PowerShellSigningTool();
                {
                    Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.ps1"));
                    Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.ps1"));
                }
            }
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new PowerShellSigningTool();
                {
                    Assert.IsTrue(File.Exists("TestFiles/signed/signed.ps1"));
                    Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.ps1"));
                }
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works()
        {
            var signingTool = new PowerShellSigningTool();
            {
                Assert.IsTrue(signingTool.IsFileSigned("Unsign_Works/signed/signed.ps1"));
                signingTool.UnsignFile("Unsign_Works/signed/signed.ps1");
                Assert.IsFalse(signingTool.IsFileSigned("Unsign_Works/signed/signed.ps1"));
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Works()
        {
            var signingTool = new PowerShellSigningTool();
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.ps1", "Certificates/SigningServer.Test.pfx", CertificatePassword);
            }
        }


        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_NoResign_Fails()
        {
            var signingTool = new PowerShellSigningTool();
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.ps1", "Certificates/SigningServer.Test.pfx", CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_NoResign_Works()
        {
            var signingTool = new PowerShellSigningTool();
            {
                CanResign(signingTool, "NoResign_Fails/signed/signed.ps1", "Certificates/SigningServer.Test.pfx", CertificatePassword);
            }
        }
    }
}
