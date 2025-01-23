using System.IO;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SigningServer.Client;
using SigningServer.Server;
using SigningServer.Server.Configuration;
using SigningServer.Signing.Configuration;

namespace SigningServer.Test;

public class RequestTrackingTest : UnitTestBase
{
    protected WebApplicationFactory<Program>? Application { get; private set; }

    [OneTimeSetUp]
    public void Setup()
    {
        Application = new WebApplicationFactory<Program>()
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
                                    CertificateName = "TestDefault",
                                    Certificate = AssemblyEvents.Certificate.Value.GetAwaiter().GetResult(),
                                    PrivateKey = AssemblyEvents.PrivateKey.Value.GetAwaiter().GetResult()
                                },
                                new CertificateConfiguration
                                {
                                    CertificateName = "user1",
                                    Username = "user1",
                                    Password = "pass1",
                                    Certificate = AssemblyEvents.Certificate.Value.GetAwaiter().GetResult(),
                                    PrivateKey = AssemblyEvents.PrivateKey.Value.GetAwaiter().GetResult()
                                }
                            },
                            WorkingDirectory = "WorkingDirectory"
                        }));
                    services.Replace(ServiceDescriptor.Singleton<ISigningRequestTracker>(
                        new TestingSigningRequestTracker()));
                });
            });
    }

    [OneTimeTearDown]
    public void Shutdown()
    {
        Application?.Dispose();
    }
    
    [Test]
    [DeploymentItem("TestFiles", "RequestTrackingTest")]
    public async Task EnsureTrackingWorks()
    {
        var tracker = (TestingSigningRequestTracker)Application!.Services.GetRequiredService<ISigningRequestTracker>();
        using (var client = new SigningClient(Application!.CreateClient(),
                   Application.Services.GetRequiredService<ILogger<SigningClient>>(),
                   Path.Combine(ExecutionDirectory, "RequestTrackingTest", "unsigned", "Unsigned.dll"),
                       Path.Combine(ExecutionDirectory, "RequestTrackingTest", "signed", "Signed.dll")))
        {
            await client.InitializeAsync();
            await client.SignFilesAsync();    
        }

        tracker.CurrentDay.Entries.Should().ContainKey("unknown-TestDefault");
        tracker.CurrentDay.Entries["unknown-TestDefault"].TotalNumberOfRequests.Should().Be(2);
        tracker.CurrentDay.Entries["unknown-TestDefault"].TotalNumberOfSignaturesCreated.Should().Be(1);
        tracker.CurrentDay.Entries["unknown-TestDefault"].TotalNumberOfSignaturesSkipped.Should().Be(1);
    }
}
