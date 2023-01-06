using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Client;
using SigningServer.Server.Configuration;
using SigningServer.Server.SigningTool;
using Program = SigningServer.Server.Program;

namespace SigningServer.Test;

[TestClass]
public class SigningServerIntegrationTest : UnitTestBase
{
    private static WebApplicationFactory<Program> _application;

    [ClassInitialize]
    public static void Setup(TestContext _)
    {
        _application = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    services.Replace(ServiceDescriptor.Singleton(
                        new SigningServerConfiguration
                        {
                            TimestampServer = TimestampServer,
                            Sha1TimestampServer = Sha1TimestampServer,
                            Certificates = new[]
                            {
                                new CertificateConfiguration
                                {
                                    Certificate = AssemblyEvents.Certificate,
                                    PrivateKey = AssemblyEvents.PrivateKey
                                }
                            },
                            WorkingDirectory = "WorkingDirectory"
                        }));
                });
            });
    }

    [ClassCleanup]
    public static void Shutdown()
    {
        _application?.Dispose();
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "IntegrationTestFiles")]
    public async Task ValidTestRun()
    {
        using (var client = new SigningClient(_application.CreateClient(),
                   Path.Combine(ExecutionDirectory, "IntegrationTestFiles/unsigned")))
        {
            await client.ConnectAsync();
            await client.SignFilesAsync();
        }

        CheckCleanupAsync();

        var signedFiles = Directory.GetFiles(Path.Combine(ExecutionDirectory, "IntegrationTestFiles"));
        var signingTools = _application.Services.GetRequiredService<ISigningToolProvider>();

        foreach (var signedFile in signedFiles)
        {
            var tool = signingTools.GetSigningTool(signedFile);
            tool.Should().NotBeNull($"Could not find signing tool for file {signedFile}");

            (await tool.IsFileSignedAsync(signedFile, CancellationToken.None)).Should().BeTrue($"File {signedFile} was not signed");
        }
    }

    private static async Task CheckCleanupAsync()
    {
        for (var retry = 0; retry < 5; retry++)
        {
            var remainingFiles = Directory.GetFiles("WorkingDirectory").Length;

            if (remainingFiles > 0)
            {
                await Task.Delay(1000);
            }
            else
            {
                return;
            }
        }
        
        Directory.GetFiles("WorkingDirectory").Should().BeEmpty("Server Side file cleanup failed");
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "HashIntegrationTestFiles")]
    public async Task ValidTestRunHashing()
    {
        foreach (var file in Directory.EnumerateFiles(Path.Combine(ExecutionDirectory, "HashIntegrationTestFiles", "unsigned")))
        {
            using var client = new SigningClient(_application.CreateClient(), file);
            client.Configuration.SignHashFileExtension = Path.GetExtension(file) + ".sig";
            client.Configuration.HashAlgorithm = "SHA256";
            await client.ConnectAsync();
            await client.SignFilesAsync();
        }

        await CheckCleanupAsync();
        
        var referenceFiles =
            new HashSet<string>(
                Directory.GetFiles(Path.Combine(ExecutionDirectory, "HashIntegrationTestFiles", "hashes"), "*.sig"));

        foreach (var referenceFile in referenceFiles.ToArray())
        {
            var signedFile = Path.Combine(ExecutionDirectory, "HashIntegrationTestFiles", "unsigned",
                Path.GetFileName(referenceFile));
            File.Exists(signedFile).Should().BeTrue();
            referenceFiles.Remove(referenceFile);

            var actualBytes = await File.ReadAllBytesAsync(signedFile);
            var expectedBytes = await File.ReadAllBytesAsync(referenceFile);
            actualBytes.Should().Equal(expectedBytes);
        }
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Parallel")]
    public async Task ParallelSigning()
    {
        using (var client = new SigningClient(_application.CreateClient(),
                   Path.Combine(ExecutionDirectory, "Parallel/unsigned")))
        {
            client.Configuration.Parallel = 4;
            await client.ConnectAsync();
            await client.SignFilesAsync();
        }

        await CheckCleanupAsync();

        var signedFiles = Directory.GetFiles(Path.Combine(ExecutionDirectory, "IntegrationTestFiles"));
        var signingTools = _application.Services.GetRequiredService<ISigningToolProvider>();

        foreach (var signedFile in signedFiles)
        {
            var tool = signingTools.GetSigningTool(signedFile);
            tool.Should().NotBeNull($"Could not find signing tool for file {signedFile}");

            (await tool.IsFileSignedAsync(signedFile, CancellationToken.None)).Should().BeTrue($"File {signedFile} was not signed");
        }
    }

    [TestMethod]
    public async Task ConcurrentSigning()
    {
        var testDir = Path.Combine(ExecutionDirectory, "IntegrationTestFiles/large");
        Directory.CreateDirectory(testDir);

        var referenceTestFile = GenerateLargeTestFile(Path.Combine(testDir, "TestFile.reference"));
        var testFiles = new string [4];
        for (var i = 0; i < testFiles.Length; i++)
        {
            var file = Path.Combine(testDir, "TestFile" + i + ".ps1");
            File.Copy(referenceTestFile, file, true);
            testFiles[i] = file;
        }

        var tasks = testFiles.Select((f, i) => Task.Run(async () =>
        {
            try
            {
                await Task.Delay(i * 50); // slight delay to trigger not exactly the same time 
                var sw = Stopwatch.StartNew();
                using (var client = new SigningClient(_application.CreateClient(), f))
                {
                    await client.ConnectAsync();
                    await client.SignFilesAsync();
                }

                return sw.Elapsed;
            }
            catch
            {
                return TimeSpan.MaxValue;
            }
        })).ToArray();

        await Task.WhenAll(tasks.ToArray<Task>());

        // check for successful signing
        var signedFiles = Directory.GetFiles(testDir, "*.ps1");
        var signingTools = _application.Services.GetRequiredService<ISigningToolProvider>();
        foreach (var signedFile in signedFiles)
        {
            var tool = signingTools.GetSigningTool(signedFile);
            tool.Should().NotBeNull($"Could not find signing tool for file {signedFile}");

            (await tool.IsFileSignedAsync(signedFile, CancellationToken.None)).Should().BeTrue($"File {signedFile} was not signed");
        }

        var times = tasks.Select(t => t.Result).ToArray();
        var average = times.Average(t => t.TotalMilliseconds);
        var threshold = times.Min(t => t.TotalMilliseconds) * 2;
        for (var i = 0; i < times.Length; i++)
        {
            if (times[i].TotalMilliseconds > threshold)
            {
                Assert.Fail(
                    $"Performance test failed, needed {times[i].TotalMilliseconds}ms for file {testFiles[i]} with average of {average} and threshold of {threshold}");
            }
        }
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "ApkIdSig")]
    public async Task TestIdSigIsDownloadedAlongApk()
    {
        using (var client = new SigningClient(_application.CreateClient(),
                   Path.Combine(ExecutionDirectory, "ApkIdSig/unsigned/unsigned-aligned.apk")))
        {
            await client.ConnectAsync();
            await client.SignFilesAsync();
        }

        await CheckCleanupAsync();

        var apk = Path.Combine(ExecutionDirectory, "ApkIdSig", "unsigned", "unsigned-aligned.apk");
        var idsig = Path.Combine(ExecutionDirectory, "ApkIdSig", "unsigned", "unsigned-aligned.apk.idsig");
        File.Exists(apk).Should().BeTrue();
        File.Exists(idsig).Should().BeTrue();
    }

    private string GenerateLargeTestFile(string path)
    {
        using var writer = new FileStream(path, FileMode.Create, FileAccess.Write);
        var size = 100 * 1024 * 1024;
        var simpleLine = Encoding.UTF8.GetBytes("Write-Host Hello World" + Environment.NewLine);
        while (size > 0)
        {
            writer.Write(simpleLine, 0, simpleLine.Length);
            size -= simpleLine.Length;
        }

        return path;
    }
}
