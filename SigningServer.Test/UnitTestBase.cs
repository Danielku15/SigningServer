using System;
using System.Diagnostics;
using FluentAssertions;
using SigningServer.Core;

namespace SigningServer.Test;

public class UnitTestBase
{
    internal static readonly string ExecutionDirectory = AppDomain.CurrentDomain.BaseDirectory;
    protected static string TimestampServer = "http://timestamp.globalsign.com/tsa/r6advanced1";
    protected static string Sha1TimestampServer = "http://timestamp.sectigo.com";

    protected void CanSign(ISigningTool signingTool, string fileName, string hashAlgorithm = null)
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
        var response = signingTool.SignFile(request);

        AssertionExtensions.Should(response.Status).Be(SignFileResponseStatus.FileSigned);
        signingTool.IsFileSigned(response.ResultFiles[0].OutputFilePath).Should().BeTrue();
        response.ResultFiles.Should().NotBeNull();
        response.ResultFiles.Count.Should().BeGreaterThan(0);
    }


    protected const string Sha1Oid = "1.3.14.3.2.26";

    protected void EnsureSignature(string fileName, string hashAlgorithmOid)
    {
        var signerInfo = CertificateHelper.GetDigitalCertificate(fileName);
        signerInfo.Should().NotBeNull();
        signerInfo.SignerInfos.Count.Should().Be(1);

        signerInfo.SignerInfos[0].DigestAlgorithm.Value.Should().Be(hashAlgorithmOid);
    }

    protected void CanResign(ISigningTool signingTool, string fileName)
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
        var response = signingTool.SignFile(request);

        AssertionExtensions.Should(response.Status).Be(SignFileResponseStatus.FileResigned);
        signingTool.IsFileSigned(fileName).Should().BeTrue();
        response.ResultFiles.Should().NotBeNull();
        response.ResultFiles.Count.Should().BeGreaterThan(0);
    }

    protected void CannotResign(ISigningTool signingTool, string fileName)
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
        var response = signingTool.SignFile(request);

        Trace.WriteLine(response);
        AssertionExtensions.Should(response.Status).Be(SignFileResponseStatus.FileAlreadySigned);
        signingTool.IsFileSigned(fileName).Should().BeTrue();
        response.ResultFiles.Should().BeNull();
    }
}
