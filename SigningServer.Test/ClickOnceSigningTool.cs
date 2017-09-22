using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NUnit.Framework;
using SigningServer.Client;
using SigningServer.Server.PE;
using SigningServer.Server.SigningTool;

namespace SigningServer.Test
{
    [TestFixture]
    public class ClickOnceSigningToolTest : UnitTestBase
    {
        [Test]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse()
        {
            var signingTool = new ClickOnceSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.application"));
            Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.application"));
        }

        [Test]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            var signingTool = new ClickOnceSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/signed/signed.application"));
            Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.application"));
        }

        [Test]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new ClickOnceSigningTool();
                {
                    Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.application"));
                    Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.application"));
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
                var signingTool = new ClickOnceSigningTool();
                {
                    Assert.IsTrue(File.Exists("TestFiles/signed/signed.application"));
                    Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.application"));
                }
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                Assert.IsTrue(signingTool.IsFileSigned("Unsign_Works/signed/signed.application"));
                signingTool.UnsignFile("Unsign_Works/signed/signed.application");
                Assert.IsFalse(signingTool.IsFileSigned("Unsign_Works/signed/signed.application"));
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Works()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.application", "Certificates/SigningServer.Test.pfx");
            }
        }


        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_NoResign_Fails()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.application", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_NoResign_Works()
        {
            var signingTool = new ClickOnceSigningTool();
            {
                CanResign(signingTool, "NoResign_Fails/signed/signed.application", "Certificates/SigningServer.Test.pfx");
            }
        }
    }
}
