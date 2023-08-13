using Microsoft.Extensions.Logging;
using SigningServer.ClientCore;

namespace SigningServer.Client;

internal class SigningClientProvider : ISigningClientProvider<SigningClientConfiguration>
{
    private readonly ILoggerFactory _loggerFactory;

    public SigningClientProvider(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }

    public SigningClient<SigningClientConfiguration> CreateClient(SigningClientConfiguration configuration)
    {
        return new SigningClient(configuration, _loggerFactory.CreateLogger<SigningClient>());
    }
}
