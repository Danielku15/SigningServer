using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using NUnit.Framework;
using SigningServer.Android;
using SigningServer.Android.Com.Android.Apksig;
using SigningServer.Core;

namespace SigningServer.Test;


public class JarSigningToolTest : UnitTestBase
{
    #region Jar

    [Test]
    public async Task IsFileSigned_UnsignedFile_Jar_ReturnsFalse()
    {
        var signingTool = new JarSigningTool();
        File.Exists("TestFiles/unsigned/unsigned.jar").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/unsigned/unsigned.jar", CancellationToken.None)).Should()
            .BeFalse();
    }

    [Test]
    public async Task IsFileSigned_SignedFile_Jar_ReturnsTrue()
    {
        var signingTool = new JarSigningTool();
        File.Exists("TestFiles/signed/signed.jar").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/signed/signed.jar", CancellationToken.None)).Should().BeTrue();
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Jar_Works()
    {
        await CanSignAsync(new JarSigningTool(), "SignFile_Works/unsigned/unsigned.jar");
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_Jar_NoResign_Fails()
    {
        await CannotResignAsync(new JarSigningTool(), "NoResign_Fails/signed/signed.jar");
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Jar_Resign_Works()
    {
        await CanResignAsync(new JarSigningTool(), "Resign_Works/signed/signed.jar");
    }

    [Test]
    [DeploymentItem("TestFiles", "Jar_Verifies")]
    public async Task SignFile_Jar_Verifies()
    {
        await TestWithVerifyAsync("Jar_Verifies/unsigned/unsigned.jar", result =>
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
    
    #endregion

    #region Aab

    [Test]
    public async Task IsFileSigned_UnsignedFile_Aab_ReturnsFalse()
    {
        var signingTool = new JarSigningTool();
        File.Exists("TestFiles/unsigned/unsigned.aab").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/unsigned/unsigned.aab", CancellationToken.None)).Should()
            .BeFalse();
    }

    [Test]
    public async Task IsFileSigned_SignedFile_Aab_ReturnsTrue()
    {
        var signingTool = new JarSigningTool();
        File.Exists("TestFiles/signed/signed.aab").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/signed/signed.aab", CancellationToken.None)).Should().BeTrue();
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Aab_Works()
    {
        await CanSignAsync(new JarSigningTool(), "SignFile_Works/unsigned/unsigned.aab");
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_Aab_NoResign_Fails()
    {
        await CannotResignAsync(new JarSigningTool(), "NoResign_Fails/signed/signed.aab");
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Aab_Resign_Works()
    {
        await CanResignAsync(new JarSigningTool(), "Resign_Works/signed/signed.aab");
    }

    [Test]
    [DeploymentItem("TestFiles", "Aab_Verifies")]
    public async Task SignFile_Aab_Verifies()
    {
        await TestWithVerifyAsync("Aab_Verifies/unsigned/unsigned.aab", result =>
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

    #endregion
    

    private async Task TestWithVerifyAsync(string fileName, Action<ApkVerifier.Result> action)
    {
        var signingTool = new JarSigningTool();
        signingTool.IsFileSupported(fileName).Should().BeTrue();

        var request = new SignFileRequest(
            fileName,
            AssemblyEvents.Certificate,
            AssemblyEvents.PrivateKey,
            string.Empty,
            TimestampServer,
            null,
            false
        );
        var response = await signingTool.SignFileAsync(request, CancellationToken.None);
        response.Status.Should().Be(SignFileResponseStatus.FileSigned);
        (await signingTool.IsFileSignedAsync(response.ResultFiles![0].OutputFilePath, CancellationToken.None)).Should()
            .BeTrue();

        var builder = new ApkVerifier.Builder(new FileInfo(response.ResultFiles[0].OutputFilePath))
            .SetMinCheckedPlatformVersion(0)
            .SetMaxCheckedPlatformVersion(0);
        var result = builder.Build().Verify();

        action(result);
    }
}
