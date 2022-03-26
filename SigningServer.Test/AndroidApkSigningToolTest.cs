using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Server.SigningTool;

namespace SigningServer.Test
{
    [TestClass]
    public class AndroidApkSigningToolTest : UnitTestBase
    {
        [TestMethod]
        public void IsFileSigned_UnsignedFile_ReturnsFalse()
        {
            var signingTool = new AndroidApkSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.jar"));
            Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.jar"));
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_ReturnsTrue()
        {
            var signingTool = new AndroidApkSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/signed/signed.jar"));
            Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.jar"));
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Jar_Works()
        {
            CanSign(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned.jar",
                "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }


        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_ApkAligned_Works()
        {
            CanSign(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned-aligned.apk",
                "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_ApkUnaligned_Works()
        {
            CanSign(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned-unaligned.apk",
                "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Jar_NoResign_Fails()
        {
            CannotResign(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed.jar",
                "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_ApkUnaligned_NoResign_Fails()
        {
            CannotResign(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed-unaligned.apk",
                "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_ApkAligned_NoResign_Fails()
        {
            CannotResign(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed-aligned.apk",
                "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_Jar_Resign_Works()
        {
            CanResign(new AndroidApkSigningTool(), "Resign_Works/signed/signed.jar",
                "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_ApkAligned_Resign_Works()
        {
            CanResign(new AndroidApkSigningTool(), "Resign_Works/signed/signed-aligned.apk",
                "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_ApkUnaligned_Resign_Works()
        {
            CannotResign(new AndroidApkSigningTool(), "Resign_Works/signed/signed-unaligned.apk",
                "Certificates/SigningServer.Test.pfx", CertificatePassword);
        }
    }
}