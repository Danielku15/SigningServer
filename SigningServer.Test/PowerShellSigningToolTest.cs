using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.MsSign;

namespace SigningServer.Test;

[TestClass]
public class PowerShellSigningToolTest : UnitTestBase
{
    [TestMethod]
    public async Task IsFileSigned_UnsignedFile_ReturnsFalse()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/unsigned/unsigned.ps1").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/unsigned/unsigned.ps1", CancellationToken.None)).Should().BeFalse();
    }

    private static PowerShellSigningTool CreateSignTool()
    {
        return new PowerShellSigningTool(AssemblyEvents.LoggerProvider.CreateLogger<PowerShellSigningTool>());
    }

    [TestMethod]
    public async Task IsFileSigned_SignedFile_ReturnsTrue()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/signed/signed.ps1").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/signed/signed.ps1", CancellationToken.None)).Should().BeTrue();
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Unsign_Works")]
    public async Task Unsign_Works()
    {
        var signingTool = CreateSignTool();
        {
            (await signingTool.IsFileSignedAsync("Unsign_Works/signed/signed.ps1", CancellationToken.None)).Should().BeTrue();
            signingTool.UnsignFile("Unsign_Works/signed/signed.ps1");
            (await signingTool.IsFileSignedAsync("Unsign_Works/signed/signed.ps1", CancellationToken.None)).Should().BeFalse();
        }
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, "SignFile_Works/unsigned/unsigned.ps1");
    }


    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, "NoResign_Fails/signed/signed.ps1");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Resign_Works()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, "Resign_Works/signed/signed.ps1");
    }
}
