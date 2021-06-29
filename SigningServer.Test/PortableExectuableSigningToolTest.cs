using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NLog;
using SigningServer.Server;
using SigningServer.Server.PE;

namespace SigningServer.Test
{
    [TestClass]
    public class PortableExectuableSigningToolTest : UnitTestBase
    {
        private static readonly Server.ILogger Log = new NLogLogger(LogManager.GetCurrentClassLogger());

        [TestMethod]
        public void IsFileSigned_UnsignedFile_UntrustedCertificate_ReturnsFalse()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
                Assert.IsFalse(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
            }
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_UntrustedCertificate_ReturnsTrue()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
                Assert.IsTrue(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
            }
        }

        [TestMethod]
        public void IsFileSigned_UnsignedFile_TrustedCertificate_ReturnsFalse()
        {
            using (
                new CertificateStoreHelper(CertificatePath, CertificatePassword, StoreName.Root,
                    StoreLocation.LocalMachine))
            {
                using (var signingTool = new PortableExectuableSigningTool(Log))
                {
                    Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
                    Assert.IsFalse(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
                }
            }
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_TrustedCertificate_ReturnsTrue()
        {
            using (
              new CertificateStoreHelper(CertificatePath, CertificatePassword, StoreName.Root,
                  StoreLocation.LocalMachine))
            {
                using (var signingTool = new PortableExectuableSigningTool(Log))
                {
                    Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
                    Assert.IsTrue(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
                }
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
	            string file = Path.Combine(ExecutionDirectory, "Unsign_Works/signed/signed.dll");
                Assert.IsTrue(signingTool.IsFileSigned(file));
                signingTool.UnsignFile(file);
                Assert.IsFalse(signingTool.IsFileSigned(file));
            }
        }

        #region Signing Works

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Exe_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.exe"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Dll_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.dll"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Cab_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.cab"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Msi_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.msi"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Sys_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.sys"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Cat_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.cat"), CertificatePath, CertificatePassword);
            }
        }

        #endregion

        #region Signing Works (Sha1)

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Exe_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), CertificatePath, CertificatePassword, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), Sha1Oid);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Dll_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), CertificatePath, CertificatePassword, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), Sha1Oid);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Cab_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), CertificatePath, CertificatePassword, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), Sha1Oid);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Msi_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), CertificatePath, CertificatePassword, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), Sha1Oid);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Sys_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), CertificatePath, CertificatePassword, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), Sha1Oid);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Cat_Works_Sha1()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cat"), CertificatePath, CertificatePassword, "SHA1");
                EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cat"), Sha1Oid);
            }
        }

        #endregion

        #region Resign Fails

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Exe_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.exe"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Dll_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.dll"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Cab_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.cab"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Msi_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.msi"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Sys_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.sys"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Cat_NoResign_Fails()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.cat"), CertificatePath, CertificatePassword);
            }
        }

        #endregion

        #region Resign Works

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Exe_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.exe"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Dll_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.dll"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Cab_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.cab"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Msi_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.msi"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Sys_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.sys"), CertificatePath, CertificatePassword);
            }
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Cat_NoResign_Works()
        {
            using (var signingTool = new PortableExectuableSigningTool(Log))
            {
                CanResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Works/signed/signed.cat"), CertificatePath, CertificatePassword);
            }
        }

        #endregion
    }
}
