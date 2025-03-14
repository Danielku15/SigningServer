using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NUnit.Framework;
using SigningServer.ClientCore;
using SigningServer.Core;
using SigningServer.Server;
using SigningServer.Server.Configuration;
using SigningServer.Signing;
using SigningServer.Signing.Configuration;
using Program = SigningServer.Server.Program;

namespace SigningServer.Test;

public interface IIntegrationTestServer : IDisposable
{
    IServiceProvider Services { get; }
    HttpClient CreateClient();
    void Start();
}

public abstract class SigningServerIntegrationTestBase : UnitTestBase
{
    protected IIntegrationTestServer? Application { get; private set; }

    [OneTimeSetUp]
    public void Setup()
    {
        Application = CreateApplication();
        Application.Start();
    }

    private IIntegrationTestServer CreateApplication()
    {
        return CreateApplicationInstance(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.Replace(ServiceDescriptor.Singleton(new SigningServerConfiguration
                {
                    TimestampServer = TimestampServer,
                    Sha1TimestampServer = Sha1TimestampServer,
                    Certificates =
                    [
                        new CertificateConfiguration
                        {
                            Certificate = AssemblyEvents.Certificate.Value.GetAwaiter().GetResult(),
                            PrivateKey = AssemblyEvents.PrivateKey.Value.GetAwaiter().GetResult()
                        }
                    ],
                    WorkingDirectory = "WorkingDirectory"
                }));
                services.Replace(ServiceDescriptor.Singleton<ISigningRequestTracker>(
                    new TestingSigningRequestTracker()));
            });
        });
    }

    protected virtual IIntegrationTestServer CreateApplicationInstance(Action<IWebHostBuilder> webHostBuilder)
    {
        return new DefaultIntegrationTestServer(webHostBuilder);
    }

    private sealed class DefaultIntegrationTestServer(Action<IWebHostBuilder> webHostBuilder) : IIntegrationTestServer
    {
        private readonly WebApplicationFactory<Program> _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(webHostBuilder);

        public void Start()
        {
            _factory.CreateClient();
        }

        public void Dispose()
        {
            _factory.Dispose();
        }
        
        public IServiceProvider Services => _factory.Services;
        
        public HttpClient CreateClient() => _factory.CreateClient();
    }


    [OneTimeTearDown]
    public void Shutdown()
    {
        Application?.Dispose();
    }

    protected abstract ISigningClient CreateSigningClient(params string[] sources);

    [Test]
    [DeploymentItem("TestFiles", "StandaloneIntegrationTestFiles")]
    public async Task ValidTestRun()
    {
        using (var client =
               CreateSigningClient(Path.Combine(ExecutionDirectory, "StandaloneIntegrationTestFiles/unsigned")))
        {
            await client.InitializeAsync();
            await client.SignFilesAsync();
        }

        await CheckCleanupAsync();

        var signedFiles = Directory.GetFiles(Path.Combine(ExecutionDirectory, "StandaloneIntegrationTestFiles"));
        var signingTools = Application!.Services.GetRequiredService<ISigningToolProvider>();

        foreach (var signedFile in signedFiles)
        {
            var tool = signingTools.GetSigningTool(signedFile);
            tool.Should().NotBeNull($"Could not find signing tool for file {signedFile}");

            (await tool!.IsFileSignedAsync(signedFile, CancellationToken.None)).Should()
                .BeTrue($"File {signedFile} was not signed");
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

    [Test]
    [DeploymentItem("TestFiles", "HashStandaloneIntegrationTestFiles")]
    public async Task ValidTestRunHashing()
    {
        foreach (var file in Directory.EnumerateFiles(Path.Combine(ExecutionDirectory,
                     "HashStandaloneIntegrationTestFiles",
                     "unsigned")))
        {
            using var client = CreateSigningClient(file);
            client.Configuration.SignHashFileExtension = Path.GetExtension(file) + ".sig";
            client.Configuration.HashAlgorithm = "SHA256";
            await client.InitializeAsync();
            await client.SignFilesAsync();
        }

        await CheckCleanupAsync();

        var referenceFiles =
            new HashSet<string>(
                Directory.GetFiles(Path.Combine(ExecutionDirectory, "HashStandaloneIntegrationTestFiles", "hashes"),
                    "*.sig"));

        foreach (var referenceFile in referenceFiles.ToArray())
        {
            var signedFile = Path.Combine(ExecutionDirectory, "HashStandaloneIntegrationTestFiles", "unsigned",
                Path.GetFileName(referenceFile));
            File.Exists(signedFile).Should().BeTrue();
            referenceFiles.Remove(referenceFile);

            var actualBytes = await File.ReadAllBytesAsync(signedFile);
            var expectedBytes = await File.ReadAllBytesAsync(referenceFile);
            actualBytes.Should().Equal(expectedBytes);
        }
    }

    [Test]
    [DeploymentItem("TestFiles", "Parallel")]
    public async Task ParallelSigning()
    {
        using (var client = CreateSigningClient(Path.Combine(ExecutionDirectory, "Parallel/unsigned")))
        {
            client.Configuration.Parallel = 4;
            await client.InitializeAsync();
            await client.SignFilesAsync();
        }

        await CheckCleanupAsync();

        var signedFiles = Directory.GetFiles(Path.Combine(ExecutionDirectory, "StandaloneIntegrationTestFiles"));
        var signingTools = Application!.Services.GetRequiredService<ISigningToolProvider>();

        foreach (var signedFile in signedFiles)
        {
            var tool = signingTools.GetSigningTool(signedFile);
            tool.Should().NotBeNull($"Could not find signing tool for file {signedFile}");

            (await tool!.IsFileSignedAsync(signedFile, CancellationToken.None)).Should()
                .BeTrue($"File {signedFile} was not signed");
        }
    }

    [Test]
    public async Task ConcurrentSigning()
    {
        var testDir = Path.Combine(ExecutionDirectory, "StandaloneIntegrationTestFiles/large");
        Directory.CreateDirectory(testDir);

        var referenceTestFile = GenerateLargeTestFile(Path.Combine(testDir, "TestFile.reference"));
        var testFiles = new string [4];
        var warmupFiles = new string[4];
        for (var i = 0; i < testFiles.Length; i++)
        {
            var file = Path.Combine(testDir, "TestFile" + i + ".ps1");
            var warmupFile = Path.Combine(testDir, "TestFile" + i + ".warmup.ps1");
            File.Copy(referenceTestFile, file, true);
            File.Copy(referenceTestFile, warmupFile, true);
            testFiles[i] = file;
            warmupFiles[i] = warmupFile;
        }
        

        foreach (var warmup in warmupFiles)
        {
            using var client = CreateSigningClient(warmup);
            await client.InitializeAsync();
            await client.SignFilesAsync();
        }

        var tasks = testFiles.Select((f, i) => Task.Run(async () =>
        {
            try
            {
                await Task.Delay(i * 50); // slight delay to trigger not exactly the same time 
                var sw = Stopwatch.StartNew();
                using (var client = CreateSigningClient(f))
                {
                    await client.InitializeAsync();
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
        var signingTools = Application!.Services.GetRequiredService<ISigningToolProvider>();
        foreach (var signedFile in signedFiles)
        {
            var tool = signingTools.GetSigningTool(signedFile);
            tool.Should().NotBeNull($"Could not find signing tool for file {signedFile}");

            (await tool!.IsFileSignedAsync(signedFile, CancellationToken.None)).Should()
                .BeTrue($"File {signedFile} was not signed");
        }

        var times = tasks.Select(t => t.Result).ToArray();
        var average = times.Average(t => t.TotalMilliseconds);
        var threshold = times.Min(t => t.TotalMilliseconds) * ConcurrentSigningAverageThresholdFactor;
        for (var i = 0; i < times.Length; i++)
        {
            if (times[i].TotalMilliseconds > threshold)
            {
                Assert.Fail(
                    $"Performance test failed, needed {times[i].TotalMilliseconds}ms for file {testFiles[i]} with average of {average} and threshold of {threshold}");
            }
        }
    }

    protected virtual int ConcurrentSigningAverageThresholdFactor => 2;

    [Test]
    [DeploymentItem("TestFiles", "ApkIdSig")]
    public async Task TestIdSigIsDownloadedAlongApk()
    {
        using (var client =
               CreateSigningClient(Path.Combine(ExecutionDirectory, "ApkIdSig/unsigned/unsigned-aligned.apk")))
        {
            await client.InitializeAsync();
            await client.SignFilesAsync();
        }

        await CheckCleanupAsync();

        var apk = Path.Combine(ExecutionDirectory, "ApkIdSig", "unsigned", "unsigned-aligned.apk");
        var idsig = Path.Combine(ExecutionDirectory, "ApkIdSig", "unsigned", "unsigned-aligned.apk.idsig");
        File.Exists(apk).Should().BeTrue();
        File.Exists(idsig).Should().BeTrue();
    }


    [Test]
    public async Task TestCertificateDownload()
    {
        using (var client = CreateSigningClient())
        {
            client.Configuration.LoadCertificatePath = Path.Combine("Certs", "Cert.pfx");
            client.Configuration.LoadCertificateExportFormat = LoadCertificateFormat.Pkcs12;
            await client.InitializeAsync();
            await client.SignFilesAsync();
        }

        var cert = Path.Combine(ExecutionDirectory, "Certs", "Cert.pfx");
        File.Exists(cert).Should().BeTrue();

        using var pfx = X509CertificateLoader.LoadPkcs12(await File.ReadAllBytesAsync(cert), null);
        pfx.Thumbprint.Should().Be((await AssemblyEvents.Certificate.Value).Thumbprint);
        pfx.HasPrivateKey.Should().BeFalse();
    }

    [Test]
    public async Task TestCertificateDownloadPemCertificate()
    {
        var certString = await TestCertificateDownloadPem(LoadCertificateFormat.PemCertificate, "CERTIFICATE");
        var cert = X509Certificate2.CreateFromPem(certString);
        cert.Thumbprint.Should().Be((await AssemblyEvents.Certificate.Value).Thumbprint);
        cert.HasPrivateKey.Should().BeFalse();
    }

    [Test]
    public async Task TestCertificateDownloadPemCertificatePublic()
    {
        var certString = await TestCertificateDownloadPem(LoadCertificateFormat.PemPublicKey, "PUBLIC KEY");
        using var cert = RSA.Create();
        cert.ImportFromPem(certString);

        cert.ExportSubjectPublicKeyInfo().Should()
            .Equal((await AssemblyEvents.Certificate.Value).PublicKey.ExportSubjectPublicKeyInfo());
    }

    private async Task<string> TestCertificateDownloadPem(LoadCertificateFormat format, string section)
    {
        using (var client = CreateSigningClient())
        {
            client.Configuration.LoadCertificatePath = Path.Combine("Certs", "Cert.pem");
            client.Configuration.LoadCertificateExportFormat = format;
            await client.InitializeAsync();
            await client.SignFilesAsync();
        }

        var cert = Path.Combine(ExecutionDirectory, "Certs", "Cert.pem");
        File.Exists(cert).Should().BeTrue();

        var pem = await File.ReadAllTextAsync(cert);
        pem.Should().ContainAll("BEGIN " + section, "END " + section);
        return pem;
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
