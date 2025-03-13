using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SigningServer.ClientCore.Configuration;

public abstract class DefaultSigningConfigurationLoader<TConfiguration>(
    IConfiguration appConfiguration,
    ILogger<DefaultSigningConfigurationLoader<TConfiguration>> logger,
    string[] commandLineArgs)
    : ISigningConfigurationLoader<TConfiguration> where TConfiguration : SigningClientConfigurationBase, new()
{
    protected abstract void BindFromIConfiguration(IConfiguration appConfiguration, TConfiguration configuration);
    
    public Task<TConfiguration?> LoadConfigurationAsync()
    {
        var loadedConfiguration = new TConfiguration();
        
        // 1. Fill from IConfiguration (e.g. environment variables but also config.json/config_custom.json )
        BindFromIConfiguration(appConfiguration, loadedConfiguration);

        // 2. Fill from Command Line
        if (!loadedConfiguration.FillFromArgs(commandLineArgs, logger))
        {
            Environment.ExitCode = ErrorCodes.InvalidConfiguration;
            return Task.FromResult<TConfiguration?>(null);
        }

        return Task.FromResult<TConfiguration?>(loadedConfiguration);
    }
}
