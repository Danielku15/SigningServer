using System.IO;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using SigningServer.Server.PE;

namespace SigningServer.Test
{
    [TestFixture]
    public class PortableExectuableSigningToolTest : UnitTestBase
    {
        [Test]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.dll"));
                Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.dll"));
            }
        }

        [Test]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                Assert.IsTrue(File.Exists("TestFiles/signed/signed.dll"));
                Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.dll"));
            }
        }

        [Test]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
            using (
                new CertificateStoreHelper("Certificates/SigningServer.Test.pfx", StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                using (var signingTool = new PortableExectuableSigningTool())
                {
                    Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.dll"));
                    Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.dll"));
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
                using (var signingTool = new PortableExectuableSigningTool())
                {
                    Assert.IsTrue(File.Exists("TestFiles/signed/signed.dll"));
                    Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.dll"));
                }
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                Assert.IsTrue(signingTool.IsFileSigned("Unsign_Works/signed/signed.dll"));
                signingTool.UnsignFile("Unsign_Works/signed/signed.dll");
                Assert.IsFalse(signingTool.IsFileSigned("Unsign_Works/signed/signed.dll"));
            }
        }

        #region Signing Works

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Exe_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.exe", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Dll_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.dll", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Cab_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.cab", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Msi_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.msi", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Sys_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, "SignFile_Works/unsigned/unsigned.sys", "Certificates/SigningServer.Test.pfx");
            }
        }

        #endregion

        #region Resign Fails

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Exe_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.exe", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Dll_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.dll", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Cab_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.cab", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Msi_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.msi", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Sys_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CannotResign(signingTool, "NoResign_Fails/signed/signed.sys", "Certificates/SigningServer.Test.pfx");
            }
        }

        #endregion

        #region Resign Works

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Exe_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanResign(signingTool, "NoResign_Works/signed/signed.exe", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Dlle_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanResign(signingTool, "NoResign_Works/signed/signed.dll", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Cab_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanResign(signingTool, "NoResign_Works/signed/signed.cab", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Msi_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanResign(signingTool, "NoResign_Works/signed/signed.msi", "Certificates/SigningServer.Test.pfx");
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Sys_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanResign(signingTool, "NoResign_Works/signed/signed.sys", "Certificates/SigningServer.Test.pfx");
            }
        }

        #endregion
    }
}
