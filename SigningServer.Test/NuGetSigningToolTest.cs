using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NuGet.Common;
using NuGet.Packaging;
using NuGet.Packaging.Signing;
using SigningServer.Server.SigningTool;
using LogLevel = NuGet.Common.LogLevel;

namespace SigningServer.Test;

[TestClass]
public class NuGetSigningToolTest : UnitTestBase
{
    [TestMethod]
    public async Task IsFileSigned_UnsignedFile_ReturnsFalse()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/unsigned/unsigned.nupkg").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/unsigned/unsigned.nupkg", CancellationToken.None)).Should()
            .BeFalse();
    }

    protected override async ValueTask CustomFileSignVerificationAsync(string outputFilePath)
    {
        var trustProviders = new ISignatureVerificationProvider[]
        {
            new IntegrityVerificationProvider(), 
            new SignatureTrustAndValidityVerificationProvider(new[]
            {
                new KeyValuePair<string, HashAlgorithmName>("3771B92C18DEDF886B8D1C76E3E5B3207B7BA2D17B358C64709A6DEA06D70523", HashAlgorithmName.SHA256)
            })
        };
        var verifier = new PackageSignatureVerifier(trustProviders);

        using var package = new PackageArchiveReader(outputFilePath);
        var verificationResult = await verifier.VerifySignaturesAsync(package,
            SignedPackageVerifierSettings.GetVerifyCommandDefaultPolicy(), CancellationToken.None);

        if (!verificationResult.IsValid)
        {
            var buffer = new StringBuilder();
            var logMessages = verificationResult.Results.SelectMany(p => p.Issues)
                .Select(p => p.AsRestoreLogMessage()).ToList();
            foreach (var msg in logMessages)
            {
                buffer.AppendLine(msg.Message);
            }

            if (logMessages.Any(m => m.Level >= NuGet.Common.LogLevel.Warning))
            {
                var errors = logMessages.Count(m => m.Level == LogLevel.Error);
                var warnings = logMessages.Count(m => m.Level == LogLevel.Warning);

                buffer.AppendLine($"Finished with {errors} errors and {warnings} warnings.");
            }

            Assert.Fail("Failed to verify nuget: {0}", buffer);
        }
    }

    private static NuGetSigningTool CreateSignTool()
    {
        return new NuGetSigningTool(AssemblyEvents.LoggerProvider.CreateLogger<NuGetSigningTool>());
    }

    [TestMethod]
    public async Task IsFileSigned_SignedFile_ReturnsTrue()
    {
        var signingTool = CreateSignTool();
        File.Exists("TestFiles/signed/signed.nupkg").Should().BeTrue();
        (await signingTool.IsFileSignedAsync("TestFiles/signed/signed.nupkg", CancellationToken.None)).Should()
            .BeTrue();
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, "SignFile_Works/unsigned/unsigned.nupkg");
    }


    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, "NoResign_Fails/signed/signed.nupkg");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Resign_Works()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, "Resign_Works/signed/signed.nupkg");
    }
}
