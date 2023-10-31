using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using NUnit.Framework;
using SigningServer.Android;
using SigningServer.Android.Com.Android.Apksig;
using SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1;
using SigningServer.Android.Com.Android.Apksig.Internal.Jar;
using SigningServer.Android.Com.Android.Apksig.Internal.Util;
using SigningServer.Core;

namespace SigningServer.Test;

public class AndroidApkSigningToolTest : UnitTestBase
{
    [Test]
    public async Task IsFileSigned_UnsignedFile_ReturnsFalse()
    {
        var signingTool = new AndroidApkSigningTool();
        File.Exists("TestFiles/unsigned/unsigned-aligned.apk").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/unsigned/unsigned-aligned.apk", CancellationToken.None))
            .Should().BeFalse();
    }

    [Test]
    public async Task IsFileSigned_SignedFile_ReturnsTrue()
    {
        var signingTool = new AndroidApkSigningTool();
        File.Exists("TestFiles/signed/signed-aligned.apk").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/signed/signed-aligned.apk", CancellationToken.None)).Should()
            .BeTrue();
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_ApkAligned_Works()
    {
        await CanSignAsync(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned-aligned.apk");
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_ApkUnaligned_Works()
    {
        await CanSignAsync(new AndroidApkSigningTool(), "SignFile_Works/unsigned/unsigned-unaligned.apk");
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_ApkUnaligned_NoResign_Fails()
    {
        await CannotResignAsync(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed-unaligned.apk");
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_ApkAligned_NoResign_Fails()
    {
        await CannotResignAsync(new AndroidApkSigningTool(), "NoResign_Fails/signed/signed-aligned.apk");
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_ApkAligned_Resign_Works()
    {
        await CanResignAsync(new AndroidApkSigningTool(), "Resign_Works/signed/signed-aligned.apk");
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_ApkUnaligned_Resign_Works()
    {
        await CannotResignAsync(new AndroidApkSigningTool(), "Resign_Works/signed/signed-unaligned.apk");
    }

    [Test]
    [DeploymentItem("TestFiles", "ApkAligned_Verifies")]
    public async Task SignFile_ApkAligned_Verifies()
    {
        var (result, _) = await TestWithVerifyAsync("ApkAligned_Verifies/unsigned/unsigned-aligned.apk");
        if (!result.IsVerified())
        {
            Assert.Fail(string.Join(Environment.NewLine, result.GetAllErrors()));
        }

        result.IsVerifiedUsingV1Scheme().Should().BeTrue();
        result.IsVerifiedUsingV2Scheme().Should().BeTrue();
        result.IsVerifiedUsingV3Scheme().Should().BeTrue();
        result.IsVerifiedUsingV4Scheme().Should().BeTrue();
    }

    [Test]
    [DeploymentItem("TestFiles", "ApkUnaligned_Verifies")]
    public async Task SignFile_ApkUnaligned_Verifies()
    {
        var (result, _) = await TestWithVerifyAsync("ApkUnaligned_Verifies/unsigned/unsigned-unaligned.apk");
        if (!result.IsVerified())
        {
            Assert.Fail(string.Join(Environment.NewLine, result.GetAllErrors()));
        }

        result.IsVerifiedUsingV1Scheme().Should().BeTrue();
        result.IsVerifiedUsingV2Scheme().Should().BeTrue();
        result.IsVerifiedUsingV3Scheme().Should().BeTrue();
        result.IsVerifiedUsingV4Scheme().Should().BeTrue();
    }

    [TestCase("unsigned-unaligned.apk", "SHA-1", DigestAlgorithm.SHA1_CASE)]
    [TestCase("unsigned-unaligned.apk", "SHA-256", DigestAlgorithm.SHA1_CASE)]
    [TestCase("unsigned-unaligned.apk", "Automatic", DigestAlgorithm.SHA1_CASE)]
    [TestCase("unsigned-unaligned.apk", "Invalid", DigestAlgorithm.SHA1_CASE)]
    [TestCase("unsigned-unaligned.apk", null, DigestAlgorithm.SHA1_CASE)]
    [TestCase("unsigned-unaligned-minsdk-24.apk", "SHA-1", DigestAlgorithm.SHA256_CASE)]
    [TestCase("unsigned-unaligned-minsdk-24.apk", "SHA-256", DigestAlgorithm.SHA256_CASE)]
    [TestCase("unsigned-unaligned-minsdk-24.apk", "Automatic", DigestAlgorithm.SHA256_CASE)]
    [TestCase("unsigned-unaligned-minsdk-24.apk", "Invalid", DigestAlgorithm.SHA256_CASE)]
    [TestCase("unsigned-unaligned-minsdk-24.apk", null, DigestAlgorithm.SHA256_CASE)]
    [DeploymentItem("TestFiles", "ApkIgnores")]
    public async Task SignFile_Ignores_HashAlgorithm(string inputFile, string? hashAlgorithm, int expectedDigestAlgorithmCase)
    {
        DigestAlgorithm expectedDigestAlgorithm;
        switch (expectedDigestAlgorithmCase)
        {
            case DigestAlgorithm.SHA1_CASE:
                expectedDigestAlgorithm = DigestAlgorithm.SHA1;
                break;
            case DigestAlgorithm.SHA256_CASE:
                expectedDigestAlgorithm = DigestAlgorithm.SHA256;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(expectedDigestAlgorithmCase));
        }
        
        var request = new SignFileRequest(
            $"ApkIgnores/unsigned/{inputFile}",
            AssemblyEvents.Certificate,
            AssemblyEvents.PrivateKey,
            string.Empty,
            TimestampServer,
            hashAlgorithm,
            false
        );
        var (result, response) = await TestWithVerifyAsync(request);
        if (!result.IsVerified())
        {
            Assert.Fail(string.Join(Environment.NewLine, result.GetAllErrors()));
        }

        result.IsVerifiedUsingV1Scheme().Should().BeTrue();

        // read the manifest from the APK and check the digest algorithm
        using var apkFile = new Android.IO.RandomAccessFile(new FileInfo(response.ResultFiles![0].OutputFilePath), "r");
        var apk = Android.Com.Android.Apksig.Util.DataSources.AsDataSource(apkFile, 0, apkFile.Length());
        var apkSections = Android.Com.Android.Apksig.Apk.ApkUtils.FindZipSections(apk);
        var cdStartOffset = apkSections.GetZipCentralDirectoryOffset();
        var cdRecords = V1SchemeVerifier.ParseZipCentralDirectory(apk, apkSections);
        var manifestEntry = cdRecords.First(r => V1SchemeConstants.MANIFEST_ENTRY_NAME.Equals(r.GetName()));
        
        var manifestBytes = Android.Com.Android.Apksig.Internal.Zip.LocalFileRecord.GetUncompressedData(apk, manifestEntry, cdStartOffset);
        var manifest = new ManifestParser(manifestBytes);
        var manifestIndividualSections = manifest.ReadAllSections();
        
        var digestName = V1SchemeSigner.GetEntryDigestAttributeName(expectedDigestAlgorithm);
        foreach (var section in manifestIndividualSections)
        {
            AssertDigest(digestName, section);
        }
    }

    private static void AssertDigest(string digestName, ManifestParser.Section section)
    {
        foreach (var attribute in section.GetAttributes())
        {
            var attributeName = attribute.GetName();
            if (attributeName.Contains("-Digest"))
            {
                Assert.AreEqual(digestName, attributeName,
                    section.GetName() + " has wrong digest type " + attributeName);
            }
        }
    }

    private Task<(ApkVerifier.Result verifyResult, SignFileResponse signFileResponse)> TestWithVerifyAsync(
        string fileName)
    {
        var request = new SignFileRequest(
            fileName,
            AssemblyEvents.Certificate,
            AssemblyEvents.PrivateKey,
            string.Empty,
            TimestampServer,
            null,
            false
        );
        return TestWithVerifyAsync(request);
    }

    private async Task<(ApkVerifier.Result verifyResult, SignFileResponse signFileResponse)> TestWithVerifyAsync(
        SignFileRequest request)
    {
        var signingTool = new AndroidApkSigningTool();
        signingTool.IsFileSupported(request.InputFilePath).Should().BeTrue();

        var response = await signingTool.SignFileAsync(request, CancellationToken.None);

        response.Status.Should().Be(SignFileResponseStatus.FileSigned);
        (await signingTool.IsFileSignedAsync(response.ResultFiles![0].OutputFilePath, CancellationToken.None)).Should()
            .BeTrue();

        var builder = new ApkVerifier.Builder(new FileInfo(response.ResultFiles[0].OutputFilePath));
        
        // ensure we validate the V1 version scheme but also have support for SHA-256 we use in tests.
        builder.SetMinCheckedPlatformVersion(AndroidSdkVersion.JELLY_BEAN_MR2);
        
        if (response.ResultFiles.Count > 1)
        {
            builder.SetV4SignatureFile(new FileInfo(response.ResultFiles[1].OutputFilePath));
        }

        var result = builder.Build().Verify();

        return (result, response);
    }
}
