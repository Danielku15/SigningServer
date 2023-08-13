using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
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
    public async Task IsFileSigned_UnsignedFile_ReturnsFalse()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/unsigned/unsigned.appx").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/unsigned/unsigned.appx", CancellationToken.None)).Should()
            .BeFalse();
    }

    private static AppxSigningTool CreateSignTool()
    {
        return new AppxSigningTool(AssemblyEvents.LoggerProvider.CreateLogger<AppxSigningTool>());
    }

    [TestMethod]
    public async Task IsFileSigned_SignedFile_ReturnsTrue()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/signed/signed.appx").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/signed/signed.appx", CancellationToken.None)).Should().BeTrue();
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, "SignFile_Works/unsigned/unsigned.appx");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Unsigned_WrongPublishedFails")]
    public async Task SignFile_Unsigned_WrongPublishedFails()
    {
        var signingTool = CreateSignTool();
        var fileName = "Unsigned_WrongPublishedFails/error/UnsignedWrongPublisher.appx";
        signingTool.IsFileSupported(fileName).Should().BeTrue();
        var request = new SignFileRequest(
            fileName,
            AssemblyEvents.Certificate,
            AssemblyEvents.PrivateKey,
            string.Empty,
            TimestampServer,
            null,
            true
        );
        var response = await signingTool.SignFileAsync(request, CancellationToken.None);
        Trace.WriteLine(response);
        response.Status.Should().Be(SignFileResponseStatus.FileNotSignedError);
        (await signingTool.IsFileSignedAsync(fileName, CancellationToken.None)).Should().BeFalse();
        response.ResultFiles.Should().BeNull();
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, "NoResign_Fails/signed/signed.appx");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Works")]
    public async Task SignFile_Signed_Resign_Works()
    {
        var signingTool = CreateSignTool();
        var fileName = "NoResign_Works/signed/signed.appx";
        signingTool.IsFileSupported(fileName).Should().BeTrue();
        var request = new SignFileRequest(
            fileName,
            AssemblyEvents.Certificate,
            AssemblyEvents.PrivateKey,
            string.Empty,
            TimestampServer,
            null,
            true
        );
        var response = await signingTool.SignFileAsync(request, CancellationToken.None);
        response.Status.Should().Be(SignFileResponseStatus.FileResigned);
        (await signingTool.IsFileSignedAsync(fileName, CancellationToken.None)).Should().BeTrue();
        response.ResultFiles.Count.Should().Be(1);
    }
}
