using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SigningServer.ClientCore.Configuration;

namespace SigningServer.Client;

internal class SigningClientConfigurationLoader(
    IConfiguration appConfiguration,
    ILogger<DefaultSigningConfigurationLoader<SigningClientConfiguration>> logger,
    string[] commandLineArgs)
    : DefaultSigningConfigurationLoader<SigningClientConfiguration>(appConfiguration, logger, commandLineArgs)
{
    protected override void BindFromIConfiguration(IConfiguration appConfiguration, SigningClientConfiguration configuration)
    {
        appConfiguration.Bind(configuration);
    }
}
