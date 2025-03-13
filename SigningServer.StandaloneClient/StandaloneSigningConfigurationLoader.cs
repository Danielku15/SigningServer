using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SigningServer.ClientCore.Configuration;

namespace SigningServer.StandaloneClient;

internal class StandaloneSigningConfigurationLoader(
    IConfiguration appConfiguration,
    ILogger<DefaultSigningConfigurationLoader<StandaloneSigningClientConfiguration>> logger,
    string[] commandLineArgs)
    : DefaultSigningConfigurationLoader<StandaloneSigningClientConfiguration>(appConfiguration, logger, commandLineArgs)
{
    protected override void BindFromIConfiguration(IConfiguration appConfiguration, StandaloneSigningClientConfiguration configuration)
    {
        appConfiguration.Bind(configuration);
    }
}
