using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SigningServer.Client;
using SigningServer.ClientCore;

namespace SigningServer.Test;


public class SigningServerIntegrationTest : SigningServerIntegrationTestBase
{
    protected override ISigningClient CreateSigningClient(params string[] sources)
    {
        return new SigningClient(Application!.CreateClient(),
            Application.Services.GetRequiredService<ILogger<SigningClient>>(), sources);
    }
}
