using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using SigningServer.Contracts;
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
            CanSign("SignFile_Works/unsigned/unsigned.exe", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Dll_Works()
        {
            CanSign("SignFile_Works/unsigned/unsigned.dll", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Cab_Works()
        {
            CanSign("SignFile_Works/unsigned/unsigned.cab", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Msi_Works()
        {
            CanSign("SignFile_Works/unsigned/unsigned.msi", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Sys_Works()
        {
            CanSign("SignFile_Works/unsigned/unsigned.sys", "Certificates/SigningServer.Test.pfx");
        }

        private void CanSign(string fileName, string pfx, bool overwriteSignature = false)
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                var certificate = new X509Certificate2(pfx);
                Assert.IsTrue(signingTool.IsFileSupported(fileName));

                var response = new SignFileResponse();
                var request = new SignFileRequest
                {
                    FileName = fileName,
                    OverwriteSignature = overwriteSignature
                };
                signingTool.SignFile(fileName, certificate, "http://timestamp.verisign.com/scripts/timstamp.dll", request, response);

                Assert.AreEqual(SignFileResponseResult.FileSigned, response.Result);
                Assert.IsTrue(signingTool.IsFileSigned(fileName));
                Assert.IsNotNull(response.FileContent);
                Assert.IsTrue(response.FileSize > 0);
                using (var data = new MemoryStream())
                {
                    using (response.FileContent)
                    {
                        response.FileContent.CopyTo(data);
                        Assert.AreEqual(response.FileSize, data.ToArray().Length);
                    }
                }
            }
        }

        #endregion

        #region Resign Fails

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Exe_NoResign_Fails()
        {
            CannotResign("NoResign_Fails/signed/signed.exe", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Dll_NoResign_Fails()
        {
            CannotResign("NoResign_Fails/signed/signed.dll", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Cab_NoResign_Fails()
        {
            CannotResign("NoResign_Fails/signed/signed.cab", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Msi_NoResign_Fails()
        {
            CannotResign("NoResign_Fails/signed/signed.msi", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Sys_NoResign_Fails()
        {
            CannotResign("NoResign_Fails/signed/signed.sys", "Certificates/SigningServer.Test.pfx");
        }

        private void CannotResign(string fileName, string pfx)
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                var certificate = new X509Certificate2(pfx);
                Assert.IsTrue(signingTool.IsFileSupported(fileName));

                var response = new SignFileResponse();
                var request = new SignFileRequest
                {
                    FileName = fileName,
                    OverwriteSignature = false
                };
                signingTool.SignFile(fileName, certificate, "http://timestamp.verisign.com/scripts/timstamp.dll", request, response);

                Trace.WriteLine(response);
                Assert.AreEqual(SignFileResponseResult.FileAlreadySigned, response.Result);
                Assert.IsTrue(signingTool.IsFileSigned(fileName));
                Assert.IsNull(response.FileContent);
                Assert.IsTrue(response.FileSize == 0);
            }
        }

        #endregion



        #region Resign Works

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Exe_NoResign_Works()
        {
            CanResign("NoResign_Works/signed/signed.exe", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Dlle_NoResign_Works()
        {
            CanResign("NoResign_Works/signed/signed.dll", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Cab_NoResign_Works()
        {
            CanResign("NoResign_Works/signed/signed.cab", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Msi_NoResign_Works()
        {
            CanResign("NoResign_Works/signed/signed.msi", "Certificates/SigningServer.Test.pfx");
        }

        [Test]
        [DeploymentItem("TestFiles", "NoResign_Works")]
        public void SignFile_Signed_Sys_NoResign_Works()
        {
            CanResign("NoResign_Works/signed/signed.sys", "Certificates/SigningServer.Test.pfx");
        }

        private void CanResign(string fileName, string pfx)
        {
            using (var signingTool = new PortableExectuableSigningTool())
            {
                var certificate = new X509Certificate2(pfx);
                Assert.IsTrue(signingTool.IsFileSupported(fileName));

                var response = new SignFileResponse();
                var request = new SignFileRequest
                {
                    FileName = fileName,
                    OverwriteSignature = true
                };
                signingTool.SignFile(fileName, certificate, "http://timestamp.verisign.com/scripts/timstamp.dll", request, response);

                Assert.AreEqual(SignFileResponseResult.FileResigned, response.Result);
                Assert.IsTrue(signingTool.IsFileSigned(fileName));
                Assert.IsNotNull(response.FileContent);
                Assert.IsTrue(response.FileSize > 0);
                using (var data = new MemoryStream())
                {
                    using (response.FileContent)
                    {
                        response.FileContent.CopyTo(data);
                        Assert.AreEqual(response.FileSize, data.ToArray().Length);
                    }
                }
            }
        }

        #endregion
    }
}
