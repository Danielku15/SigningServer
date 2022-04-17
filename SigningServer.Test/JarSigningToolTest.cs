using System;
using System.Diagnostics;
using System.IO;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android;
using SigningServer.Android.Com.Android.Apksig;
using SigningServer.Contracts;

namespace SigningServer.Test
{
    [TestClass]
    public class JarSigningToolTest : UnitTestBase
    {
        [TestMethod]
        public void IsFileSigned_UnsignedFile_ReturnsFalse()
        {
            var signingTool = new JarSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.jar"));
            Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.jar"));
        }

        [TestMethod]
        public void IsFileSigned_SignedFile_ReturnsTrue()
        {
            var signingTool = new JarSigningTool();
            Assert.IsTrue(File.Exists("TestFiles/signed/signed.jar"));
            Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.jar"));
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "SignFile_Works")]
        public void SignFile_Unsigned_Jar_Works()
        {
            CanSign(new JarSigningTool(), "SignFile_Works/unsigned/unsigned.jar");
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "NoResign_Fails")]
        public void SignFile_Signed_Jar_NoResign_Fails()
        {
            CannotResign(new JarSigningTool(), "NoResign_Fails/signed/signed.jar");
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Resign_Works")]
        public void SignFile_Signed_Jar_Resign_Works()
        {
            CanResign(new JarSigningTool(), "Resign_Works/signed/signed.jar");
        }

        [TestMethod]
        [DeploymentItem("TestFiles", "Jar_Verifies")]
        public void SignFile_Jar_Verifies()
        {
            TestWithVerify("Jar_Verifies/unsigned/unsigned.jar", result =>
            {
                if (!result.IsVerified())
                {
                    Assert.Fail(string.Join(Environment.NewLine, result.GetAllErrors()));
                }
                result.IsVerifiedUsingV1Scheme().Should().BeTrue();
                result.IsVerifiedUsingV2Scheme().Should().BeFalse();
                result.IsVerifiedUsingV3Scheme().Should().BeFalse();
                result.IsVerifiedUsingV4Scheme().Should().BeFalse();
            });
        }

        private void TestWithVerify(string fileName, Action<ApkVerifier.Result> action)
        {
            var signingTool = new JarSigningTool();
            signingTool.IsFileSupported(fileName).Should().BeTrue();

            var response = new SignFileResponse();
            var request = new SignFileRequest
            {
                FileName = fileName,
                OverwriteSignature = false
            };
            signingTool.SignFile(fileName, AssemblyEvents.Certificate, TimestampServer, request, response);

            Trace.WriteLine(response);
            try
            {
                response.Result.Should().Be(SignFileResponseResult.FileSigned);
                signingTool.IsFileSigned(fileName).Should().BeTrue();

                var builder = new ApkVerifier.Builder(new FileInfo(fileName))
                    .SetMinCheckedPlatformVersion(0)
                    .SetMaxCheckedPlatformVersion(0);
                var result = builder.Build().Verify();

                action(result);
            }
            finally
            {
                response.Dispose();
            }
        }
    }
}