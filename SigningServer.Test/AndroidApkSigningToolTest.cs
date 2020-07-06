using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NUnit.Framework;
using SigningServer.Server.SigningTool;

namespace SigningServer.Test
{
    [TestFixture]
    public class AndroidApkSigningToolTest : UnitTestBase
    {
	    [Test]
        public void ManifestWriterTestSingleLine()
        {
            var ms = new MemoryStream();
            ms.WriteManifestLine("123456789_123456789_123456789_123456789_");

            Assert.AreEqual("123456789_123456789_123456789_123456789_\r\n", Encoding.UTF8.GetString(ms.ToArray()));
        }

        [Test]
        public void ManifestWriterTestTwoLines()
        {
            var ms = new MemoryStream();
            ms.WriteManifestLine("123456789_123456789_123456789_123456789_123456789_123456789_123456789_123456789_");

            Assert.AreEqual("123456789_123456789_123456789_123456789_123456789_123456789_123456789_\r\n 123456789_\r\n", Encoding.UTF8.GetString(ms.ToArray()));
        }

        [Test]
        public void ManifestWriterTestThreeLines()
        {
            var ms = new MemoryStream();
            ms.WriteManifestLine(
                "123456789_123456789_123456789_123456789_123456789_123456789_123456789_123456789_" +
                "123456789_123456789_123456789_123456789_123456789_123456789_123456789_123456789_"
            );

            Assert.AreEqual("123456789_123456789_123456789_123456789_123456789_123456789_123456789_\r\n" +
                            " 123456789_123456789_123456789_123456789_123456789_123456789_123456789\r\n" +
                            " _123456789_123456789_\r\n", Encoding.UTF8.GetString(ms.ToArray()));
        }


        [Test]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse()
        {
            var signingTool = new AndroidApkSigningTool();
            string file = $"{ExecutionDirectory}/TestFiles/unsigned/unsigned.jar";
            Assert.IsTrue(File.Exists(file));
            Assert.IsFalse(signingTool.IsFileSigned(file));
        }

        [Test]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            var signingTool = new AndroidApkSigningTool();
            string file = $"{ExecutionDirectory}/TestFiles/signed/signed.jar";
            Assert.IsTrue(File.Exists(file));
            Assert.IsTrue(signingTool.IsFileSigned(file));
        }

        [Test]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
	        using (
                new CertificateStoreHelper(CertificatePath, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new AndroidApkSigningTool();
                string unsignedFilePath = Path.Combine(ExecutionDirectory, "TestFiles", "unsigned", "unsigned.jar");
                Assert.IsTrue(File.Exists(unsignedFilePath));
                Assert.IsFalse(signingTool.IsFileSigned(unsignedFilePath));
            }
        }

        [Test]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue()
        {
	        using (
              new CertificateStoreHelper(CertificatePath, StoreName.Root,
                  StoreLocation.LocalMachine))
            {
                var signingTool = new AndroidApkSigningTool();
                string signedFilePath = Path.Combine(ExecutionDirectory, "TestFiles", "signed", "signed.jar");
                Assert.IsTrue(File.Exists(signedFilePath));
                Assert.IsTrue(signingTool.IsFileSigned(signedFilePath));
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works()
        {
            var signingTool = new AndroidApkSigningTool();
            String testFile = Path.Combine(ExecutionDirectory, "Unsign_Works/signed/signed.jar");
            Assert.IsTrue(signingTool.IsFileSigned(testFile));
            signingTool.UnsignFile(testFile);
            Assert.IsFalse(signingTool.IsFileSigned(testFile));
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Jar_Works()
        {
	        string inputFile = Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.jar");
            CanSign(new AndroidApkSigningTool(), inputFile, CertificatePath);
        }


        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Jar_NoResign_Fails()
        {
	        string inputFile = Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.jar");
            CannotResign(new AndroidApkSigningTool(), inputFile, CertificatePath);
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Jar_NoResign_Works()
        {
	        string inputFile = Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.jar");
            CanResign(new AndroidApkSigningTool(), inputFile, CertificatePath);
        }
    }
}
