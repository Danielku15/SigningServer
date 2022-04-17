using System.Diagnostics;
using System.IO;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Contracts;
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
        var response = new SignFileResponse();
        var request = new SignFileRequest
        {
            FileName = fileName,
            OverwriteSignature = true
        };
        signingTool.SignFile(fileName, AssemblyEvents.Certificate, 
            AssemblyEvents.PrivateKey,
            TimestampServer, request,
            response);
        Trace.WriteLine(response);
        Assert.AreEqual(SignFileResponseResult.FileNotSignedError, response.Result);
        Assert.IsFalse(signingTool.IsFileSigned(fileName));
        Assert.IsInstanceOfType(response.FileContent, typeof(MemoryStream));
        Assert.AreEqual(response.FileSize, response.FileContent.Length);
        Assert.AreEqual(0, response.FileSize);
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
        var response = new SignFileResponse();
        var request = new SignFileRequest
        {
            FileName = fileName,
            OverwriteSignature = true
        };
        signingTool.SignFile(fileName, AssemblyEvents.Certificate, 
            AssemblyEvents.PrivateKey,
            TimestampServer, request,
            response);
        Trace.WriteLine(response);
        Assert.AreEqual(SignFileResponseResult.FileResigned, response.Result);
        Assert.IsTrue(signingTool.IsFileSigned(fileName));
        Assert.IsInstanceOfType(response.FileContent, typeof(FileStream));
    } 
}