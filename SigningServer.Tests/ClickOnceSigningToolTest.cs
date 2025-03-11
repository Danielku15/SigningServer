using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SigningServer.ClickOnce;

namespace SigningServer.Test;


public class ClickOnceSigningToolTest : UnitTestBase
{
    #region .application

    [Test]
    public async Task Application_IsFileSigned_UnsignedFile_ReturnsFalse_Application()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/unsigned/unsigned.application").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/unsigned/unsigned.application", CancellationToken.None))
            .Should().BeFalse();
    }

    private static ClickOnceSigningTool CreateSignTool()
    {
        return new ClickOnceSigningTool(AssemblyEvents.LoggerProvider.CreateLogger<ClickOnceSigningTool>());
    }

    [Test]
    public async Task Application_IsFileSigned_SignedFile_ReturnsTrue_Application()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/signed/signed.application").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/signed/signed.application", CancellationToken.None)).Should()
            .BeTrue();
    }

    [Test]
    [DeploymentItem("TestFiles", "Unsign_Works")]
    public async Task Application_Unsign_Works_Application()
    {
        var signingTool = CreateSignTool();
        {
            (await signingTool.IsFileSignedAsync("Unsign_Works/signed/signed.application", CancellationToken.None))
                .Should().BeTrue();
            signingTool.UnsignFile("Unsign_Works/signed/signed.application");
            (await signingTool.IsFileSignedAsync("Unsign_Works/signed/signed.application", CancellationToken.None))
                .Should().BeFalse();
        }
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task Application_SignFile_Unsigned_Works_Application()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, "SignFile_Works/unsigned/unsigned.application");
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task Application_SignFile_Signed_NoResign_Fails_Application()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, "NoResign_Fails/signed/signed.application");
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task Application_SignFile_Signed_Resign_Works_Application()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, "Resign_Works/signed/signed.application");
    }

    #endregion

    #region .manifest

    [Test]
    public async Task Manifest_IsFileSigned_UnsignedFile_ReturnsFalse_Manifest()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/unsigned/unsigned.exe.manifest").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/unsigned/unsigned.exe.manifest", CancellationToken.None))
            .Should().BeFalse();
    }

    [Test]
    public async Task Manifest_IsFileSigned_SignedFile_ReturnsTrue_Manifest()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/signed/signed.exe.manifest").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/signed/signed.exe.manifest", CancellationToken.None)).Should()
            .BeTrue();
    }

    [Test]
    [DeploymentItem("TestFiles", "Unsign_Works")]
    public async Task Manifest_Unsign_Works_Manifest()
    {
        var signingTool = CreateSignTool();
        {
            (await signingTool.IsFileSignedAsync("Unsign_Works/signed/signed.exe.manifest", CancellationToken.None))
                .Should().BeTrue();
            signingTool.UnsignFile("Unsign_Works/signed/signed.exe.manifest");
            (await signingTool.IsFileSignedAsync("Unsign_Works/signed/signed.exe.manifest", CancellationToken.None))
                .Should().BeFalse();
        }
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task Manifest_SignFile_Unsigned_Works_Manifest()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, "SignFile_Works/unsigned/unsigned.exe.manifest");
    }


    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task Manifest_SignFile_Signed_NoResign_Fails_Manifest()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, "NoResign_Fails/signed/signed.exe.manifest");
    }


    [Test]
    [DeploymentItem("TestFiles", "Resign_Fails")]
    public async Task Manifest_SignFile_Signed_Resign_Works_Manifest()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, "Resign_Fails/signed/signed.exe.manifest");
    }

    #endregion
}
