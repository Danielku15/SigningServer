using System.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.MsSign;

namespace SigningServer.Test;

[TestClass]
public class PowerShellSigningToolTest : UnitTestBase
{
    [TestMethod]
    public void IsFileSigned_UnsignedFile_ReturnsFalse()
    {
        var signingTool = CreateSignTool();
        Assert.IsTrue(File.Exists("TestFiles/unsigned/unsigned.ps1"));
        Assert.IsFalse(signingTool.IsFileSigned("TestFiles/unsigned/unsigned.ps1"));
    }

    private static PowerShellSigningTool CreateSignTool()
    {
        return new PowerShellSigningTool(new NullLogger<PowerShellSigningTool>());
    }

    [TestMethod]
    public void IsFileSigned_SignedFile_ReturnsTrue()
    {
        var signingTool = CreateSignTool();
        Assert.IsTrue(File.Exists("TestFiles/signed/signed.ps1"));
        Assert.IsTrue(signingTool.IsFileSigned("TestFiles/signed/signed.ps1"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Unsign_Works")]
    public void Unsign_Works()
    {
        var signingTool = CreateSignTool();
        {
            Assert.IsTrue(signingTool.IsFileSigned("Unsign_Works/signed/signed.ps1"));
            signingTool.UnsignFile("Unsign_Works/signed/signed.ps1");
            Assert.IsFalse(signingTool.IsFileSigned("Unsign_Works/signed/signed.ps1"));
        }
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void SignFile_Unsigned_Works()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, "SignFile_Works/unsigned/unsigned.ps1");
    }


    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void SignFile_Signed_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, "NoResign_Fails/signed/signed.ps1");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public void SignFile_Signed_Resign_Works()
    {
        var signingTool = CreateSignTool();
        CanResign(signingTool, "Resign_Works/signed/signed.ps1");
    }
}