using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
            Console.WriteLine("usage: SigningServer.StandaloneClient [options] [Source1 Source2 Source3 ...]");
            StandaloneSigningClientConfiguration.PrintUsage(Console.Out);
            return;
        }

        using var host = Host.CreateDefaultBuilder( /* No Args */)
            .UseSigningClientConfiguration(args)
            .ConfigureServices(services =>
            {
                services.AddSingleton<ISigningConfigurationLoader<StandaloneSigningClientConfiguration>>(sp =>
                    ActivatorUtilities.CreateInstance<StandaloneSigningConfigurationLoader>(sp,
                        [args]));
                services.AddSingleton<ISigningClientProvider<StandaloneSigningClientConfiguration>, SigningClientProvider>();
                services.AddSingleton<IHashSigningTool, ManagedHashSigningTool>();
                services.AddSingleton<ISigningToolProvider, DefaultSigningToolProvider>();
                services.AddSingleton<SigningClientRunner<StandaloneSigningClientConfiguration>>();
            })
            .Build();
        
        if (Environment.ExitCode != 0)
        {
            return;
        }

        await host.StartAsync();

        var loader = host.Services.GetRequiredService<SigningClientRunner<StandaloneSigningClientConfiguration>>();
        await loader.RunAsync();
        await host.StopAsync();
    }
}
