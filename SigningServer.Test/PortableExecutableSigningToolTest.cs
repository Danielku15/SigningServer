using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Server.SigningTool;

namespace SigningServer.Test
{
    [TestClass]
    public class PortableExecutableSigningToolTest : UnitTestBase
    {
        [TestMethod]
        public void IsFileSigned_UnsignedFile_ReturnsFalse()
        {
            var signingTool = new PortableExecutableSigningTool();
            Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
            Assert.IsFalse(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_ReturnsTrue()
        {
            var signingTool = new PortableExecutableSigningTool();
            Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
            Assert.IsTrue(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Unsign_Works")]
        public void Unsign_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            string file = Path.Combine(ExecutionDirectory, "Unsign_Works/signed/signed.dll");
            Assert.IsTrue(signingTool.IsFileSigned(file));
            signingTool.UnsignFile(file);
            Assert.IsFalse(signingTool.IsFileSigned(file));
        }

        #region Signing Works

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Exe_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.exe"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Dll_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.dll"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Cab_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.cab"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Msi_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.msi"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Sys_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.sys"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Cat_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.cat"), CertificatePath, CertificatePassword);
        }

        #endregion

        #region Signing Works (Sha1)

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Exe_Works_Sha1()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), CertificatePath, CertificatePassword, "SHA1");
            EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), Sha1Oid);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Dll_Works_Sha1()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), CertificatePath, CertificatePassword, "SHA1");
            EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), Sha1Oid);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Cab_Works_Sha1()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), CertificatePath, CertificatePassword, "SHA1");
            EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), Sha1Oid);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Msi_Works_Sha1()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), CertificatePath, CertificatePassword, "SHA1");
            EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), Sha1Oid);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Sys_Works_Sha1()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), CertificatePath, CertificatePassword, "SHA1");
            EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), Sha1Oid);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
        public void SignFile_Unsigned_Cat_Works_Sha1()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cat"), CertificatePath, CertificatePassword, "SHA1");
            EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cat"), Sha1Oid);
        }

        #endregion

        #region Resign Fails

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Exe_NoResign_Fails()
        {
            var signingTool = new PortableExecutableSigningTool();
            CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.exe"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Dll_NoResign_Fails()
        {
            var signingTool = new PortableExecutableSigningTool();
            CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.dll"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Cab_NoResign_Fails()
        {
            var signingTool = new PortableExecutableSigningTool();
            CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.cab"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Msi_NoResign_Fails()
        {
            var signingTool = new PortableExecutableSigningTool();
            CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.msi"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Sys_NoResign_Fails()
        {
            var signingTool = new PortableExecutableSigningTool();
            CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.sys"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Cat_NoResign_Fails()
        {
            var signingTool = new PortableExecutableSigningTool();
            CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.cat"), CertificatePath, CertificatePassword);
        }

        #endregion

        #region Resign Works

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_Exe_Resign_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.exe"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_Dll_Resign_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.dll"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_Cab_Resign_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.cab"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_Msi_Resign_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.msi"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_Sys_Resign_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.sys"), CertificatePath, CertificatePassword);
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_Cat_Resign_Works()
        {
            var signingTool = new PortableExecutableSigningTool();
            CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.cat"), CertificatePath, CertificatePassword);
        }

        #endregion
    }
}
