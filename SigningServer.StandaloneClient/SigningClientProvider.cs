using Microsoft.Extensions.Logging;
using SigningServer.ClientCore;
using SigningServer.Signing;

namespace SigningServer.StandaloneClient;

internal class SigningClientProvider : ISigningClientProvider<StandaloneSigningClientConfiguration>
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly IHashSigningTool _hashSigningTool;
    private readonly ISigningToolProvider _signingToolProvider;

    public SigningClientProvider(ILoggerFactory loggerFactory, IHashSigningTool hashSigningTool, ISigningToolProvider signingToolProvider)
    {
        _loggerFactory = loggerFactory;
        _hashSigningTool = hashSigningTool;
        _signingToolProvider = signingToolProvider;
    }

    public SigningClient<StandaloneSigningClientConfiguration> CreateClient(
        StandaloneSigningClientConfiguration configuration)
    {
        return new StandaloneSigningClient(configuration, _loggerFactory.CreateLogger<StandaloneSigningClient>(),
            _hashSigningTool,
            _signingToolProvider);
    }
}
