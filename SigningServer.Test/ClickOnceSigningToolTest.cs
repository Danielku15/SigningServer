using System.IO;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.ClickOnce;

namespace SigningServer.Test;

[TestClass]
public class ClickOnceSigningToolTest : UnitTestBase
{
    #region .application

    [TestMethod]
    public void Application_IsFileSigned_UnsignedFile_ReturnsFalse_Application()
    {
        var signingTool = CreateSignTool();
        Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.application"));
        Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.application"));
    }

    private static ClickOnceSigningTool CreateSignTool()
    {
        return new ClickOnceSigningTool(AssemblyEvents.LoggerProvider.CreateLogger<ClickOnceSigningTool>());
    }

    [TestMethod]
    public void Application_IsFileSigned_SignedFile_ReturnsTrue_Application()
    {
        var signingTool = CreateSignTool();
        Assert.IsTrue(File.Exists("TestFiles/signed/signed.application"));
        Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.application"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Unsign_Works")]
    public void Application_Unsign_Works_Application()
    {
        var signingTool = CreateSignTool();
        {
            Assert.IsTrue(signingTool.IsFileSigned("Unsign_Works/signed/signed.application"));
            signingTool.UnsignFile("Unsign_Works/signed/signed.application");
            Assert.IsFalse(signingTool.IsFileSigned("Unsign_Works/signed/signed.application"));
        }
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void Application_SignFile_Unsigned_Works_Application()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, "SignFile_Works/unsigned/unsigned.application");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void Application_SignFile_Signed_NoResign_Fails_Application()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, "NoResign_Fails/signed/signed.application");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public void Application_SignFile_Signed_Resign_Works_Application()
    {
        var signingTool = CreateSignTool();
        CanResign(signingTool, "Resign_Works/signed/signed.application");
    }

    #endregion

    #region .manifest

    [TestMethod]
    public void Manifest_IsFileSigned_UnsignedFile_ReturnsFalse_Manifest()
    {
        var signingTool = CreateSignTool();
        Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.exe.manifest"));
        Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.exe.manifest"));
    }

    [TestMethod]
    public void Manifest_IsFileSigned_SignedFile_ReturnsTrue_Manifest()
    {
        var signingTool = CreateSignTool();
        Assert.IsTrue(File.Exists("TestFiles/signed/signed.exe.manifest"));
        Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.exe.manifest"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Unsign_Works")]
    public void Manifest_Unsign_Works_Manifest()
    {
        var signingTool = CreateSignTool();
        {
            Assert.IsTrue(signingTool.IsFileSigned("Unsign_Works/signed/signed.exe.manifest"));
            signingTool.UnsignFile("Unsign_Works/signed/signed.exe.manifest");
            Assert.IsFalse(signingTool.IsFileSigned("Unsign_Works/signed/signed.exe.manifest"));
        }
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void Manifest_SignFile_Unsigned_Works_Manifest()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, "SignFile_Works/unsigned/unsigned.exe.manifest");
    }


    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void Manifest_SignFile_Signed_NoResign_Fails_Manifest()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, "NoResign_Fails/signed/signed.exe.manifest");
    }


    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Fails")]
    public void Manifest_SignFile_Signed_Resign_Works_Manifest()
    {
        var signingTool = CreateSignTool();
        CanResign(signingTool, "Resign_Fails/signed/signed.exe.manifest");
    }

    #endregion
}
