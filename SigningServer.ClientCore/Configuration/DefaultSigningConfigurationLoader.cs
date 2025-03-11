using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SigningServer.ClientCore.Configuration;

public class DefaultSigningConfigurationLoader<TConfiguration>(
    IConfiguration appConfiguration,
    ILogger<DefaultSigningConfigurationLoader<TConfiguration>> logger,
    string[] commandLineArgs)
    : ISigningConfigurationLoader<TConfiguration> where TConfiguration : SigningClientConfigurationBase, new()
{
    public async Task<TConfiguration?> LoadConfigurationAsync()
    {
        var loadedConfiguration = new TConfiguration();
        // 1.. Fill from IConfiguration (e.g. environment variables )
        appConfiguration.Bind(loadedConfiguration);

        // 2. Load from configuration files
        if (!await LoadConfigurationFromFileAsync(loadedConfiguration))
        {
            Environment.ExitCode = ErrorCodes.InvalidConfiguration;
            return null;
        }

        // 3. Fill from Command Line
        if (!loadedConfiguration.FillFromArgs(commandLineArgs, logger))
        {
            Environment.ExitCode = ErrorCodes.InvalidConfiguration;
            return null;
        }

        return loadedConfiguration;
    }

    private async Task<bool> LoadConfigurationFromFileAsync(TConfiguration loadedConfiguration)
    {
        var hasCustomConfig = false;
        var args = commandLineArgs;
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith('-'))
            {
                switch (arg.ToLowerInvariant())
                {
                    case "-c":
                    case "--config":
                        if (i + 1 < args.Length)
                        {
                            if (!await LoadConfigurationFromJson(loadedConfiguration, args[i + 1], false))
                            {
                                return false;
                            }

                            i++;
                        }
                        else
                        {
                            logger.LogError("Config could not be loaded: No filename provided");
                            return false;
                        }

                        break;
                }
            }
        }

        if (!hasCustomConfig)
        {
            await LoadConfigurationFromJson(loadedConfiguration, "config.json", true);
        }

        return true;
    }

    private async Task<bool> LoadConfigurationFromJson(TConfiguration loadedConfiguration, string file, bool optional)
    {
        var realPath = ConfigFilePathCandidates
            .Select(c => Path.Combine(c, file))
            .FirstOrDefault(File.Exists);

        if (realPath == null && optional)
        {
            return true;
        }

        if (realPath == null && !optional)
        {
            logger.LogError("Could not find config file '{ConfigFile}'. Checked: {Candidates}", file,
                string.Join(", ", ConfigFilePathCandidates));
            return false;
        }

        try
        {
            logger.LogTrace("Loading configuration from {ConfigFile}", realPath);

            var json = await File.ReadAllTextAsync(realPath!);
            JsonPopulate.PopulateObject(json, typeof(TConfiguration), loadedConfiguration, JsonOptions);

            logger.LogTrace("Loaded configuration from {ConfigFile}", realPath);
            return true;
        }
        catch (Exception e)
        {
            logger.LogError(e, "Config could not be loaded from {ConfigFile}", file);
            return false;
        }
    }

    // ReSharper disable once StaticMemberInGenericType
    private static string[] ConfigFilePathCandidates =>
    [
        Environment.CurrentDirectory,
        AppContext.BaseDirectory
    ];

    // ReSharper disable once StaticMemberInGenericType
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PreferredObjectCreationHandling = JsonObjectCreationHandling.Populate,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };
}
