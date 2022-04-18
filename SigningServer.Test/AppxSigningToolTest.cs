using System.Diagnostics;
using System.IO;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
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
        Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.appx"));
        Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.appx"));
    }

    private static AppxSigningTool CreateSignTool()
    {
        return new AppxSigningTool(new NullLogger<AppxSigningTool>());
    }

    [TestMethod]
    public void IsFileSigned_SignedFile_ReturnsTrue()
    {
        var signingTool = CreateSignTool();
        Assert.IsTrue(File.Exists("TestFiles/signed/signed.appx"));
        Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.appx"));
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
        Assert.IsTrue(signingTool.IsFileSupported(fileName));
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
        Assert.AreEqual(SignFileResponseStatus.FileNotSignedError, response.Status);
        Assert.IsFalse(signingTool.IsFileSigned(fileName));
        Assert.IsNull(response.ResultFiles);
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
        Assert.IsTrue(signingTool.IsFileSupported(fileName));
        var request = new SignFileRequest
        {
            InputFilePath = fileName,
            Certificate = AssemblyEvents.Certificate,
            PrivateKey = AssemblyEvents.PrivateKey,
            OverwriteSignature = true
        };
        var response = signingTool.SignFile(request);
        Assert.AreEqual(SignFileResponseStatus.FileResigned, response.Status);
        Assert.IsTrue(signingTool.IsFileSigned(fileName));
        response.ResultFiles.Count.Should().Be(1);
    }
}
