using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Server.SigningTool;

namespace SigningServer.Test
{
    [TestClass]
    public class AndroidApkSigningToolTest : UnitTestBase
    {
        [TestMethod]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse()
        {
            var signingTool = new AndroidApkSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.jar"));
            Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.jar"));
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            var signingTool = new AndroidApkSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/signed/signed.jar"));
            Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.jar"));
        }

        [TestMethod]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new AndroidApkSigningTool();
                Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.jar"));
                Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.jar"));
            }
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue()
        {
            using (
              new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", CertificatePassword, StoreName.Root,
                  StoreLocation.LocalMachine))
            {
                var signingTool = new AndroidApkSigningTool();
                Assert.IsTrue(File.Exists("TestFiles/signed/signed.jar"));
                Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.jar"));
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Jar_Works()
        {
            CanSign(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned.jar", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }


        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_ApkAligned_Works()
        {
            CanSign(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned-aligned.apk", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_ApkUnaligned_Works()
        {
            CanSign(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned-unaligned.apk", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Jar_NoResign_Fails()
        {
            CannotResign(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed.jar", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_ApkUnaligned_NoResign_Fails()
        {
            CannotResign(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed-unaligned.apk", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_ApkAligned_NoResign_Fails()
        {
            CannotResign(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed-aligned.apk", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Jar_NoResign_Works()
        {
            CanResign(new AndroidApkSigningTool(), "NoResign_Works/signed/signed.jar", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_ApkAligned_NoResign_Works()
        {
            CanResign(new AndroidApkSigningTool(), "NoResign_Works/signed/signed-aligned.apk", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_ApkUnaligned_NoResign_Works()
        {
            CanResign(new AndroidApkSigningTool(), "NoResign_Works/signed/signed-unaligned.apk", "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }
    }
}