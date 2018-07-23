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
        public void ManifestReaderMultiline()
        {
            var manifest = new Manifest();
            using (var fs = File.OpenRead("TestFiles/unsigned/MultiLineManifest.mf"))
            {
                manifest.Read(fs);
            }

            var expectedText = File.ReadAllText("TestFiles/unsigned/MultiLineManifest.mf");
            var ms = new MemoryStream();
            manifest.Write(ms, null);
            var actualText = Encoding.UTF8.GetString(ms.ToArray());
            Assert.AreEqual(expectedText, actualText);
        }


        [Test]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse()
        {
            var signingTool = new AndroidApkSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.jar"));
            Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.jar"));
        }

        [Test]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            var signingTool = new AndroidApkSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/signed/signed.jar"));
            Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.jar"));
        }

        [Test]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                var signingTool = new AndroidApkSigningTool();
                Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.jar"));
                Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.jar"));
            }
        }

        [Test]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue()
        {
            using (
              new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", StoreName.Root,
                  StoreLocation.LocalMachine))
            {
                var signingTool = new AndroidApkSigningTool();
                Assert.IsTrue(File.Exists("TestFiles/signed/signed.jar"));
                Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.jar"));
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works()
        {
            var signingTool = new AndroidApkSigningTool();
            Assert.IsTrue(signingTool.IsFileSigned("Unsign_Works/signed/signed.jar"));
            signingTool.UnsignFile("Unsign_Works/signed/signed.jar");
            Assert.IsFalse(signingTool.IsFileSigned("Unsign_Works/signed/signed.jar"));
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Jar_Works()
        {
            CanSign(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned.jar", "Certificates/SigningServer.Test.pfx");
        }


        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Jar_NoResign_Fails()
        {
            CannotResign(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed.jar", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Jar_NoResign_Works()
        {
            CanResign(new AndroidApkSigningTool(), "NoResign_Works/signed/signed.jar", "Certificates/SigningServer.Test.pfx");
        }
    }
}
