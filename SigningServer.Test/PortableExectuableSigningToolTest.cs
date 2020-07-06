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
                Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
                Assert.IsFalse(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
            }
        }

        [Test]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
                Assert.IsTrue(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
            }
        }

        [Test]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
            using (
                new CertificateStoreHelper(CertificatePath, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                using (var signingTool = new PortableExectuableSigningTool())
                {
                    Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
                    Assert.IsFalse(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
                }
            }
        }

        [Test]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue()
        {
            using (
              new CertificateStoreHelper(CertificatePath, StoreName.Root,
                  StoreLocation.LocalMachine))
            {
                using (var signingTool = new PortableExectuableSigningTool())
                {
                    Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
                    Assert.IsTrue(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
                }
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
	            string file = Path.Combine(ExecutionDirectory, "Unsign_Works/signed/signed.dll");
                Assert.IsTrue(signingTool.IsFileSigned(file));
                signingTool.UnsignFile(file);
                Assert.IsFalse(signingTool.IsFileSigned(file));
            }
        }

        #region Signing Works

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Exe_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.exe"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Dll_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.dll"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Cab_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.cab"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Msi_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.msi"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Sys_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.sys"), CertificatePath);
            }
        }

        #endregion

        #region Signing Works (Sha1)

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Exe_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), CertificatePath, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), Sha1Oid);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Dll_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), CertificatePath, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), Sha1Oid);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Cab_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), CertificatePath, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), Sha1Oid);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Msi_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), CertificatePath, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), Sha1Oid);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Sys_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), CertificatePath, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), Sha1Oid);
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
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.exe"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Dll_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.dll"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Cab_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.cab"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Msi_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.msi"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Sys_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.sys"), CertificatePath);
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
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.exe"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Dlle_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.dll"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Cab_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.cab"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Msi_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.msi"), CertificatePath);
            }
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Sys_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.sys"), CertificatePath);
            }
        }

        #endregion
    }
}
