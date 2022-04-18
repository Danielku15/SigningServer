using System.Diagnostics;
using System.IO;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Core;
using SigningServer.MsSign;

namespace SigningServer.Test;

[TestClass]
public class AppxSigningToolTest : UnitTestBase
{
    [TestMethod]
    public void IsFileSigned_UnsignedFile_ReturnsFalse()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/unsigned/unsigned.appx").Should().BeTrue();
        signingTool.IsFileSigned("TestFiles/unsigned/unsigned.appx").Should().BeFalse();
    }

    private static AppxSigningTool CreateSignTool()
    {
        return new AppxSigningTool(AssemblyEvents.LoggerProvider.CreateLogger<AppxSigningTool>());
    }

    [TestMethod]
    public void IsFileSigned_SignedFile_ReturnsTrue()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/signed/signed.appx").Should().BeTrue();
        signingTool.IsFileSigned("TestFiles/signed/signed.appx").Should().BeTrue();
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void SignFile_Unsigned_Works()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, "SignFile_Works/unsigned/unsigned.appx");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Unsigned_WrongPublishedFails")]
    public void SignFile_Unsigned_WrongPublishedFails()
    {
        var signingTool = CreateSignTool();
        var fileName = "Unsigned_WrongPublishedFails/error/UnsignedWrongPublisher.appx";
        signingTool.IsFileSupported(fileName).Should().BeTrue();
        var request = new SignFileRequest
        {
            InputFilePath = fileName,
            Certificate = AssemblyEvents.Certificate,
            PrivateKey = AssemblyEvents.PrivateKey,
            TimestampServer = TimestampServer,
            OverwriteSignature = true
        };
        var response = signingTool.SignFile(request);
        Trace.WriteLine(response);
        AssertionExtensions.Should(response.Status).Be(SignFileResponseStatus.FileNotSignedError);
        signingTool.IsFileSigned(fileName).Should().BeFalse();
        response.ResultFiles.Should().BeNull();
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void SignFile_Signed_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, "NoResign_Fails/signed/signed.appx");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Works")]
    public void SignFile_Signed_Resign_Works()
    {
        var signingTool = CreateSignTool();
        var fileName = "NoResign_Works/signed/signed.appx";
        signingTool.IsFileSupported(fileName).Should().BeTrue();
        var request = new SignFileRequest
        {
            InputFilePath = fileName,
            Certificate = AssemblyEvents.Certificate,
            PrivateKey = AssemblyEvents.PrivateKey,
            OverwriteSignature = true
        };
        var response = signingTool.SignFile(request);
        AssertionExtensions.Should(response.Status).Be(SignFileResponseStatus.FileResigned);
        signingTool.IsFileSigned(fileName).Should().BeTrue();
        response.ResultFiles.Count.Should().Be(1);
    }
}
