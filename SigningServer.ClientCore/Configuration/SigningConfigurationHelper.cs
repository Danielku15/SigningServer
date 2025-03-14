using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NLog;
using NLog.Config;
using NLog.Extensions.Logging;
using NLog.Targets;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace SigningServer.ClientCore.Configuration;

public static class SigningConfigurationHelper
{
    public static IHostBuilder UseSigningClientConfiguration(this IHostBuilder host,
        string[] args)
    {
        return host
            .ConfigureAppConfiguration(config =>
            {
                ConfigureAppConfiguration(config, args);
            })
            .UseSigningClientLogging();
    }

    private static void ConfigureAppConfiguration(IConfigurationBuilder config, string[] args)
    {
        foreach (var envSources in config.Sources.OfType<EnvironmentVariablesConfigurationSource>().ToArray())
        {
            config.Sources.Remove(envSources);
        }

        config.AddEnvironmentVariables("SIGNINGSERVER_CLIENT_");

        AddJsonFileFromArgs(config, args);
    }

    private static IHostBuilder UseSigningClientLogging(this IHostBuilder host)
    {
        return host.ConfigureServices((ctx, services) =>
        {
            var options = new NLogProviderOptions();
            options.Configure(ctx.Configuration.GetSection("Logging:NLog"));

            services.AddLogging(log =>
            {
                log.SetMinimumLevel(LogLevel.Trace);
                log.ClearProviders();
            });

            services.Replace(ServiceDescriptor.Singleton<ILoggerFactory, NLogLoggerFactory>(serviceProvider => new
                NLogLoggerFactory(CreateNLogLoggerProvider(serviceProvider, ctx.Configuration,
                    options))));
        });
    }

    private static NLogLoggerProvider CreateNLogLoggerProvider(IServiceProvider serviceProvider,
        IConfiguration hostConfiguration,
        NLogProviderOptions options)
    {
        var provider = new NLogLoggerProvider(options, LogManager.LogFactory);

        provider.LogFactory.Setup()
            .SetupExtensions(ext => ext.RegisterConfigSettings(hostConfiguration));

        provider.LogFactory.ServiceRepository.RegisterService(typeof(IServiceProvider), serviceProvider);

        if (!TryLoadConfigurationFromSection(provider, hostConfiguration))
        {
            provider.LogFactory.Setup().LoadConfiguration(configBuilder =>
            {
                if (configBuilder.Configuration.LoggingRules.Count == 0 &&
                    configBuilder.Configuration.AllTargets.Count == 0)
                {
                    configBuilder.Configuration = BuildDefaultNLogConfig(provider.LogFactory);
                }
            });
        }

        if (provider.Options.ShutdownOnDispose || !provider.Options.AutoShutdown)
        {
            provider.LogFactory.AutoShutdown = false;
        }

        return provider;
    }

    private static LoggingConfiguration BuildDefaultNLogConfig(LogFactory logfa)
    {
        var configuration = new LoggingConfiguration(logfa);
        var consoleTarget = new ColoredConsoleTarget("console")
        {
            Layout = "${longdate} ${level} - ${message} ${exception:format=ToString}", EnableAnsiOutput = true
        };
        configuration.AddTarget(consoleTarget);

        configuration.AddRule(NLog.LogLevel.Trace,
            NLog.LogLevel.Off,
            consoleTarget);

        return configuration;
    }

    private static bool TryLoadConfigurationFromSection(NLogLoggerProvider loggerProvider, IConfiguration configuration)
    {
        if (string.IsNullOrEmpty(loggerProvider.Options.LoggingConfigurationSectionName))
        {
            return false;
        }

        var nlogConfig = configuration.GetSection(loggerProvider.Options.LoggingConfigurationSectionName);
        if (!nlogConfig.Exists())
        {
            return false;
        }

        loggerProvider.LogFactory.Setup().LoadConfiguration(configBuilder =>
        {
            if (configBuilder.Configuration.LoggingRules.Count == 0 &&
                configBuilder.Configuration.AllTargets.Count == 0)
            {
                configBuilder.Configuration = new NLogLoggingConfiguration(nlogConfig, loggerProvider.LogFactory);
            }
        });
        return true;
    }

    private static bool ParseCustomConfigFromArgs(string[] args, out string? customConfig)
    {
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
                            customConfig = args[i + 1];
                            return true;
                        }

                        customConfig = null;
                        return true;
                }
            }
        }

        customConfig = null;
        return false;
    }

    private static string[] ConfigFilePathCandidates =>
    [
        Environment.CurrentDirectory,
        AppContext.BaseDirectory
    ];

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PreferredObjectCreationHandling = JsonObjectCreationHandling.Populate,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private const string DefaultConfigFileName = "config.json";

    private static string? ResolveConfigFilePath(string file)
    {
        var realPath = SigningConfigurationHelper.ConfigFilePathCandidates
            .Select(c => Path.Combine(c, file))
            .FirstOrDefault(File.Exists);
        return realPath;
    }

    private static void AddJsonFileFromArgs(IConfigurationBuilder config, string[] args)
    {
        if (ParseCustomConfigFromArgs(args, out var customConfig))
        {
            if (string.IsNullOrEmpty(customConfig))
            {
                // fail fast on missing configuration file parameter
                Console.Error.WriteLine("Custom Config could not be loaded: No filename provided");
                Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                return;
            }

            var resolvedConfig = ResolveConfigFilePath(customConfig);

            if (string.IsNullOrEmpty(resolvedConfig))
            {
                // fail fast on missing configuration file 
                Console.Error.WriteLine(
                    $"Custom Config could not be loaded: No file '{customConfig}' found in paths {string.Join(", ", ConfigFilePathCandidates)}");
                Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                return;
            }

            config.AddJsonFile(resolvedConfig);
        }
        else
        {
            var resolvedConfig = ResolveConfigFilePath(DefaultConfigFileName);
            if (!string.IsNullOrEmpty(resolvedConfig))
            {
                config.AddJsonFile(resolvedConfig);
            }
        }
    }
}
