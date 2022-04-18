using System;
using System.IO;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android;
using SigningServer.Android.Com.Android.Apksig;
using SigningServer.Core;

namespace SigningServer.Test;

[TestClass]
public class JarSigningToolTest : UnitTestBase
{
    [TestMethod]
    public void IsFileSigned_UnsignedFile_ReturnsFalse()
    {
        var signingTool = new JarSigningTool();
        File.Exists("TestFiles/unsigned/unsigned.jar").Should().BeTrue();
        signingTool.IsFileSigned("TestFiles/unsigned/unsigned.jar").Should().BeFalse();
    }

    [TestMethod]
    public void IsFileSigned_SignedFile_ReturnsTrue()
    {
        var signingTool = new JarSigningTool();
        File.Exists("TestFiles/signed/signed.jar").Should().BeTrue();
        signingTool.IsFileSigned("TestFiles/signed/signed.jar").Should().BeTrue();
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

        var request = new SignFileRequest
        {
            InputFilePath = fileName,
            Certificate = AssemblyEvents.Certificate,
            PrivateKey = AssemblyEvents.PrivateKey,
            TimestampServer = TimestampServer,
            OverwriteSignature = false
        };
        var response = signingTool.SignFile(request);
        response.Status.Should().Be(SignFileResponseStatus.FileSigned);
        signingTool.IsFileSigned(response.ResultFiles[0].OutputFilePath).Should().BeTrue();

        var builder = new ApkVerifier.Builder(new FileInfo(response.ResultFiles[0].OutputFilePath))
            .SetMinCheckedPlatformVersion(0)
            .SetMaxCheckedPlatformVersion(0);
        var result = builder.Build().Verify();

        action(result);
    }
}
