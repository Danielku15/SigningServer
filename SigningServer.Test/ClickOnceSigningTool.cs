using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Client;
using SigningServer.Server.PE;
using SigningServer.Server.SigningTool;

namespace SigningServer.Test
{
    [TestClass]
    public class ClickOnceSigningToolTest : UnitTestBase
    {
        #region .application
        [TestMethod]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse_Application()
        {
            var signingTool = new ClickOnceSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.application"));
            Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.application"));
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue_Application()
        {
            var signingTool = new ClickOnceSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/signed/signed.application"));
            Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.application"));
        }

        [TestMethod]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse_Application()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new ClickOnceSigningTool();
                {
                    Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.application"));
                    Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.application"));
                }
            }
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue_Application()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new ClickOnceSigningTool();
                {
                    Assert.IsTrue(File.Exists("TestFiles/signed/signed.application"));
                    Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.application"));
                }
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works_Application()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                Assert.IsTrue(signingTool.IsFileSigned("Unsign_Works/signed/signed.application"));
                signingTool.UnsignFile("Unsign_Works/signed/signed.application");
                Assert.IsFalse(signingTool.IsFileSigned("Unsign_Works/signed/signed.application"));
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Works_Application()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.application", "Certificates/SigningServer.Test.pfx", CertificatePassword);
            }
        }


        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_NoResign_Fails_Application()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.application", "Certificates/SigningServer.Test.pfx", CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_NoResign_Works_Application()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                CanResign(signingTool, "NoResign_Fails/signed/signed.application", "Certificates/SigningServer.Test.pfx", CertificatePassword);
            }
        }

        #endregion      
        
        #region .manifest
        [TestMethod]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse_Manifest()
        {
            var signingTool = new ClickOnceSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.exe.manifest"));
            Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.exe.manifest"));
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue_Manifest()
        {
            var signingTool = new ClickOnceSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/signed/signed.exe.manifest"));
            Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.exe.manifest"));
        }

        [TestMethod]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse_Manifest()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new ClickOnceSigningTool();
                {
                    Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.exe.manifest"));
                    Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.exe.manifest"));
                }
            }
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue_Manifest()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new ClickOnceSigningTool();
                {
                    Assert.IsTrue(File.Exists("TestFiles/signed/signed.exe.manifest"));
                    Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.exe.manifest"));
                }
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works_Manifest()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                Assert.IsTrue(signingTool.IsFileSigned("Unsign_Works/signed/signed.exe.manifest"));
                signingTool.UnsignFile("Unsign_Works/signed/signed.exe.manifest");
                Assert.IsFalse(signingTool.IsFileSigned("Unsign_Works/signed/signed.exe.manifest"));
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Works_Manifest()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.exe.manifest", "Certificates/SigningServer.Test.pfx", CertificatePassword);
            }
        }


        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_NoResign_Fails_Manifest()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.exe.manifest", "Certificates/SigningServer.Test.pfx", CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_NoResign_Works_Manifest()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                CanResign(signingTool, "NoResign_Fails/signed/signed.exe.manifest", "Certificates/SigningServer.Test.pfx", CertificatePassword);
            }
        }

        #endregion
    }
}
