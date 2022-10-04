using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android;
using SigningServer.Android.Com.Android.Apksig;
using SigningServer.Core;

namespace SigningServer.Test;

[TestClass]
public class AndroidApkSigningToolTest : UnitTestBase
{
    [TestMethod]
    public async Task IsFileSigned_UnsignedFile_ReturnsFalse()
    {
        var signingTool = new AndroidApkSigningTool();
        File.Exists("TestFiles/unsigned/unsigned-aligned.apk").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/unsigned/unsigned-aligned.apk", CancellationToken.None))
            .Should().BeFalse();
    }

    [TestMethod]
    public async Task IsFileSigned_SignedFile_ReturnsTrue()
    {
        var signingTool = new AndroidApkSigningTool();
        File.Exists("TestFiles/signed/signed-aligned.apk").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/signed/signed-aligned.apk", CancellationToken.None)).Should()
            .BeTrue();
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_ApkAligned_Works()
    {
        await CanSignAsync(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned-aligned.apk");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_ApkUnaligned_Works()
    {
        await CanSignAsync(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned-unaligned.apk");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_ApkUnaligned_NoResign_Fails()
    {
        await CannotResignAsync(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed-unaligned.apk");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_ApkAligned_NoResign_Fails()
    {
        await CannotResignAsync(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed-aligned.apk");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_ApkAligned_Resign_Works()
    {
        await CanResignAsync(new AndroidApkSigningTool(), "Resign_Works/signed/signed-aligned.apk");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_ApkUnaligned_Resign_Works()
    {
        await CannotResignAsync(new AndroidApkSigningTool(), "Resign_Works/signed/signed-unaligned.apk");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "ApkAligned_Verifies")]
    public async Task SignFile_ApkAligned_Verifies()
    {
        await TestWithVerifyAsync("ApkAligned_Verifies/unsigned/unsigned-aligned.apk", result =>
        {
            if (!result.IsVerified())
            {
                Assert.Fail(string.Join(Environment.NewLine, result.GetAllErrors()));
            }

            result.IsVerifiedUsingV1Scheme().Should().BeTrue();
            result.IsVerifiedUsingV2Scheme().Should().BeTrue();
            result.IsVerifiedUsingV3Scheme().Should().BeTrue();
            result.IsVerifiedUsingV4Scheme().Should().BeTrue();
        });
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "ApkUnaligned_Verifies")]
    public async Task SignFile_ApkUnaligned_Verifies()
    {
        await TestWithVerifyAsync("ApkUnaligned_Verifies/unsigned/unsigned-unaligned.apk", result =>
        {
            if (!result.IsVerified())
            {
                Assert.Fail(string.Join(Environment.NewLine, result.GetAllErrors()));
            }

            result.IsVerifiedUsingV1Scheme().Should().BeTrue();
            result.IsVerifiedUsingV2Scheme().Should().BeTrue();
            result.IsVerifiedUsingV3Scheme().Should().BeTrue();
            result.IsVerifiedUsingV4Scheme().Should().BeTrue();
        });
    }

    private async Task TestWithVerifyAsync(string fileName, Action<ApkVerifier.Result> action)
    {
        var signingTool = new AndroidApkSigningTool();
        signingTool.IsFileSupported(fileName).Should().BeTrue();

        var request = new SignFileRequest
        {
            InputFilePath = fileName,
            OverwriteSignature = false,
            Certificate = AssemblyEvents.Certificate,
            PrivateKey = AssemblyEvents.PrivateKey,
            TimestampServer = TimestampServer
        };
        var response = await signingTool.SignFileAsync(request, CancellationToken.None);

        response.Status.Should().Be(SignFileResponseStatus.FileSigned);
        (await signingTool.IsFileSignedAsync(response.ResultFiles[0].OutputFilePath, CancellationToken.None)).Should()
            .BeTrue();

        var builder = new ApkVerifier.Builder(new FileInfo(response.ResultFiles[0].OutputFilePath));

        if (response.ResultFiles.Count > 1)
        {
            builder.SetV4SignatureFile(new FileInfo(response.ResultFiles[1].OutputFilePath));
        }

        var result = builder.Build().Verify();

        action(result);
    }
}
