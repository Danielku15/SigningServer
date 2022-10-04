using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using SigningServer.Core;

namespace SigningServer.Test;

public class UnitTestBase
{
    internal static readonly string ExecutionDirectory = AppDomain.CurrentDomain.BaseDirectory;
    protected const string TimestampServer = "http://timestamp.globalsign.com/tsa/r6advanced1";
    protected const string Sha1TimestampServer = "http://timestamp.sectigo.com";

    protected async Task CanSignAsync(ISigningTool signingTool, string fileName, string hashAlgorithm = null)
    {
        signingTool.IsFileSupported(fileName).Should().BeTrue();

        var timestampServer = "SHA1".Equals(hashAlgorithm, StringComparison.OrdinalIgnoreCase)
            ? Sha1TimestampServer
            : TimestampServer;

        var request = new SignFileRequest
        {
            InputFilePath = fileName,
            OverwriteSignature = false,
            HashAlgorithm = hashAlgorithm,
            Certificate = AssemblyEvents.Certificate,
            PrivateKey = AssemblyEvents.PrivateKey,
            TimestampServer = timestampServer
        };
        var response = await signingTool.SignFileAsync(request, CancellationToken.None);

        response.Status.Should().Be(SignFileResponseStatus.FileSigned);
        (await signingTool.IsFileSignedAsync(response.ResultFiles[0].OutputFilePath, CancellationToken.None)).Should()
            .BeTrue();
        await CustomFileSignVerificationAsync(response.ResultFiles[0].OutputFilePath);
        response.ResultFiles.Should().NotBeNull();
        response.ResultFiles.Count.Should().BeGreaterThan(0);
    }

    protected virtual ValueTask CustomFileSignVerificationAsync(string outputFilePath)
    {
        return ValueTask.CompletedTask;
    }


    protected const string Sha1Oid = "1.3.14.3.2.26";

    protected void EnsureSignature(string fileName, string hashAlgorithmOid)
    {
        var signerInfo = CertificateHelper.GetDigitalCertificate(fileName);
        signerInfo.Should().NotBeNull();
        signerInfo.SignerInfos.Count.Should().Be(1);

        signerInfo.SignerInfos[0].DigestAlgorithm.Value.Should().Be(hashAlgorithmOid);
    }

    protected async Task CanResignAsync(ISigningTool signingTool, string fileName)
    {
        signingTool.IsFileSupported(fileName).Should().BeTrue();

        var request = new SignFileRequest
        {
            InputFilePath = fileName,
            OverwriteSignature = true,
            Certificate = AssemblyEvents.Certificate,
            PrivateKey = AssemblyEvents.PrivateKey,
            TimestampServer = TimestampServer
        };
        var response = await signingTool.SignFileAsync(request, CancellationToken.None);

        response.Status.Should().Be(SignFileResponseStatus.FileResigned);
        (await signingTool.IsFileSignedAsync(fileName, CancellationToken.None)).Should().BeTrue();
        await CustomFileSignVerificationAsync(fileName);
        response.ResultFiles.Should().NotBeNull();
        response.ResultFiles.Count.Should().BeGreaterThan(0);
    }

    protected async Task CannotResignAsync(ISigningTool signingTool, string fileName)
    {
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

        Trace.WriteLine(response);
        response.Status.Should().Be(SignFileResponseStatus.FileAlreadySigned);
        (await signingTool.IsFileSignedAsync(fileName, CancellationToken.None)).Should().BeTrue();
        await CustomFileSignVerificationAsync(fileName);
        response.ResultFiles.Should().BeNull();
    }
}
