using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NLog.Web;
using SigningServer.ClientCore;
using SigningServer.ClientCore.Configuration;

namespace SigningServer.Client;

internal static class Program
{
    private static async Task Main(string[] args)
    {
        if (args.Length == 0 || args.Any(a => a is "/?" or "--help" or "-?" or "-help" or "-h"))
        {
            Console.WriteLine("usage: SigningServer.StandaloneClient [options] [Source1 Source2 Source3 ...]");
            SigningClientConfiguration.PrintUsage(Console.Out);
            return;
        }

        using var host = Host.CreateDefaultBuilder( /* No Args */)
            .ConfigureLogging(log =>
            {
                log.SetMinimumLevel(LogLevel.Trace);
                log.ClearProviders();
                log.AddNLogWeb();
            })
            .ConfigureAppConfiguration(config =>
            {
                foreach (var envSources in config.Sources.OfType<EnvironmentVariablesConfigurationSource>().ToArray())
                {
                    config.Sources.Remove(envSources);
                }
                config.AddEnvironmentVariables("SIGNINGSERVER_CLIENT_");
                config.AddJsonFile(Path.Combine(AppContext.BaseDirectory, "config.json"), optional: true);
            })
            .ConfigureServices(services =>
            {
                services.AddSingleton<ISigningConfigurationLoader<SigningClientConfiguration>>(sp =>
                    ActivatorUtilities.CreateInstance<DefaultSigningConfigurationLoader<SigningClientConfiguration>>(sp,
                        new object[] { args }));
                services.AddSingleton<ISigningClientProvider<SigningClientConfiguration>, SigningClientProvider>();
                services.AddSingleton<SigningClientRunner<SigningClientConfiguration>>();
            })
            .UseNLog()
            .Build();

        await host.StartAsync();

        var loader = host.Services.GetRequiredService<SigningClientRunner<SigningClientConfiguration>>();
        await loader.RunAsync();
        await host.StopAsync();
    }
}
