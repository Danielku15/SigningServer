using System;
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
                                    CertificateName = "Cert2",
                                    Credentials = new[]
                                    {
                                        new CertificateAccessCredentials
                                        {
                                            Username = "user1",
                                            Password = "pass1",   
                                        }
                                    },
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

        tracker.CurrentDay.Entries.Should().ContainKey("Anonymous-TestDefault");
        tracker.CurrentDay.Entries["Anonymous-TestDefault"].TotalNumberOfRequests.Should().Be(2);
        tracker.CurrentDay.Entries["Anonymous-TestDefault"].TotalNumberOfSignaturesCreated.Should().Be(1);
        tracker.CurrentDay.Entries["Anonymous-TestDefault"].TotalNumberOfSignaturesSkipped.Should().Be(1);
        
        using (var client = new SigningClient(Application!.CreateClient(),
                   Application.Services.GetRequiredService<ILogger<SigningClient>>(),
                   Path.Combine(ExecutionDirectory, "RequestTrackingTest", "unsigned", "Unsigned.exe"),
                   Path.Combine(ExecutionDirectory, "RequestTrackingTest", "signed", "Signed.exe")))
        {
            client.Configuration.Username = "user1";
            client.Configuration.Password = "pass1";
            await client.InitializeAsync();
            await client.SignFilesAsync();    
        }

        tracker.CurrentDay.Entries.Should().ContainKey("user1-Cert2");
        tracker.CurrentDay.Entries["user1-Cert2"].TotalNumberOfRequests.Should().Be(2);
        tracker.CurrentDay.Entries["user1-Cert2"].TotalNumberOfSignaturesCreated.Should().Be(1);
        tracker.CurrentDay.Entries["user1-Cert2"].TotalNumberOfSignaturesSkipped.Should().Be(1);

        
        using (var client = new SigningClient(Application!.CreateClient(),
                   Application.Services.GetRequiredService<ILogger<SigningClient>>(),
                   Path.Combine(ExecutionDirectory, "RequestTrackingTest", "unsigned", "Unsigned.exe")))
        {
            client.Configuration.Username = "invalid";
            client.Configuration.Password = "invalid";
            await client.InitializeAsync();
            try
            {
                await client.SignFilesAsync();
                Assert.Fail("Expected error because of invalid credentials");
            }
            catch (UnauthorizedAccessException)
            {
                // expected
            }
        }

        tracker.CurrentDay.Entries.Should().ContainKey("invalid");
        tracker.CurrentDay.Entries["invalid"].TotalNumberOfRequests.Should().Be(1);
        tracker.CurrentDay.Entries["invalid"].TotalNumberOfSignaturesCreated.Should().Be(0);
        tracker.CurrentDay.Entries["invalid"].TotalNumberOfSignaturesSkipped.Should().Be(1);
    }
}
