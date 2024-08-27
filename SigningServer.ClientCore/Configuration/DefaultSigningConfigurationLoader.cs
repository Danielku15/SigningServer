using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SigningServer.ClientCore.Configuration;

public class DefaultSigningConfigurationLoader<TConfiguration> : ISigningConfigurationLoader<TConfiguration>
    where TConfiguration : SigningClientConfigurationBase, new()
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<DefaultSigningConfigurationLoader<TConfiguration>> _logger;
    private readonly string[] _commandLineArgs;

    public DefaultSigningConfigurationLoader(IConfiguration configuration,
        ILogger<DefaultSigningConfigurationLoader<TConfiguration>> logger,
        string[] commandLineArgs)
    {
        _configuration = configuration;
        _logger = logger;
        _commandLineArgs = commandLineArgs;
    }

    public async Task<TConfiguration?> LoadConfigurationAsync()
    {
        // 1. Load from files
        var configuration = await LoadConfigurationFromFileAsync();
        if (configuration == null)
        {
            return null;
        }

        // 2. Fill from IConfiguration
        _configuration.Bind(configuration);

        // 3. Fill from Command Line
        if (!configuration.FillFromArgs(_commandLineArgs, _logger))
        {
            Environment.ExitCode = ErrorCodes.InvalidConfiguration;
            return null;
        }

        return configuration;
    }

    private async Task<TConfiguration?> LoadConfigurationFromFileAsync()
    {
        var configuration = new TConfiguration();

        var defaultConfigFilePath = Path.Combine(AppContext.BaseDirectory, "config.json");
        if (File.Exists(defaultConfigFilePath))
        {
            try
            {
                _logger.LogTrace("Loading config.json");
                configuration =
                    JsonSerializer.Deserialize<TConfiguration>(
                        await File.ReadAllTextAsync(defaultConfigFilePath),
                        new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true,
                            Converters =
                            {
                                new JsonStringEnumConverter()
                            }
                        })!;
                _logger.LogTrace("Configuration loaded from config.json");
                return configuration;
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Config could not be loaded");
                Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                return null;
            }
        }

        var args = _commandLineArgs;
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("-"))
            {
                switch (arg.ToLowerInvariant())
                {
                    case "-c":
                    case "--config":
                        if (i + 1 < args.Length)
                        {
                            try
                            {
                                _logger.LogTrace("Loading config from {fileName}", args[i + 1]);
                                configuration =
                                    JsonSerializer.Deserialize<TConfiguration>(
                                        await File.ReadAllTextAsync(args[i + 1]), new JsonSerializerOptions
                                        {
                                            PropertyNameCaseInsensitive = true,
                                            Converters =
                                            {
                                                new JsonStringEnumConverter()
                                            }
                                        })!;
                                _logger.LogTrace("Configuration loaded from {fileName}", args[i + 1]);
                            }
                            catch (Exception e)
                            {
                                _logger.LogError(e, "Config could not be loaded from {fileName}", args[i + 1]);
                                Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                                return null;
                            }

                            i++;
                        }
                        else
                        {
                            _logger.LogError("Config could not be loaded: No filename provided");
                            Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                            return null;
                        }

                        break;
                }
            }
        }

        return configuration;
    }
}
