using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NLog.Web;
using SigningServer.ClientCore;
using SigningServer.ClientCore.Configuration;
using SigningServer.Signing;

namespace SigningServer.StandaloneClient;

internal static class Program
{
    private static async Task Main(string[] args)
    {
        if (args.Length == 0 || args.Any(a => a is "/?" or "--help" or "-?" or "-help" or "-h"))
        {
            Console.WriteLine("usage: SigningServer.Client.exe [options] [Source1 Source2 Source3 ...]");
            StandaloneSigningClientConfiguration.PrintUsage(Console.Out);
            return;
        }

        using var host = Host.CreateDefaultBuilder( /* No Args */)
            .ConfigureAppConfiguration(config =>
            {
                config.AddJsonFile("config.json", optional: true);
            })
            .ConfigureServices(services =>
            {
                services.AddSingleton<ISigningConfigurationLoader<StandaloneSigningClientConfiguration>>(sp =>
                    ActivatorUtilities.CreateInstance<DefaultSigningConfigurationLoader<StandaloneSigningClientConfiguration>>(sp,
                        new object[] { args }));
                services.AddSingleton<ISigningClientProvider<StandaloneSigningClientConfiguration>, SigningClientProvider>();
                services.AddSingleton<IHashSigningTool, ManagedHashSigningTool>();
                services.AddSingleton<ISigningToolProvider, DefaultSigningToolProvider>();
                services.AddSingleton<SigningClientRunner<StandaloneSigningClientConfiguration>>();
            })
            .UseNLog()
            .Build();

        await host.StartAsync();

        var loader = host.Services.GetRequiredService<SigningClientRunner<StandaloneSigningClientConfiguration>>();
        await loader.RunAsync();
        await host.StopAsync();
    }
}
