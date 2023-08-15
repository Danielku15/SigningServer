using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SigningServer.ClientCore;
using SigningServer.Signing;
using SigningServer.Signing.Configuration;
using SigningServer.StandaloneClient;

namespace SigningServer.Test;


public class StandaloneSigningServerIntegrationTest: SigningServerIntegrationTestBase
{
    protected override ISigningClient CreateSigningClient(params string[] sources)
    {
        return new StandaloneSigningClient(
            new StandaloneSigningClientConfiguration
            {
                TimestampServer = TimestampServer,
                WorkingDirectory = Path.GetFullPath("StandaloneWorkingDirectory"),
                Server = new CertificateConfiguration
                {
                    SigningServer = new SigningServerApiConfiguration
                    {
                        HttpClient = Application!.CreateClient()
                    }
                },
                Sources = sources
            }, Application.Services.GetRequiredService<ILogger<StandaloneSigningClient>>(),
            new ManagedHashSigningTool(),
            new DefaultSigningToolProvider(Application.Services.GetRequiredService<ILoggerFactory>()));
    }
}
