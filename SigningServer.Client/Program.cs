using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SigningServer.ClientCore;
using SigningServer.ClientCore.Configuration;

namespace SigningServer.Client;

internal static class Program
{
    private static async Task Main(string[] args)
    {
        if (args.Length == 0 || args.Any(a => a is "/?" or "--help" or "-?" or "-help" or "-h"))
        {
            Console.WriteLine("usage: SigningServer.Client [options] [Source1 Source2 Source3 ...]");
            Console.WriteLine("options: ");
            SigningClientConfiguration.PrintUsage(Console.Out);
            return;
        }

        using var host = Host.CreateDefaultBuilder( /* No Args */)
            .UseSigningClientConfiguration(args)
            .ConfigureServices(services =>
            {
                services.AddSingleton<ISigningConfigurationLoader<SigningClientConfiguration>>(sp =>
                    ActivatorUtilities.CreateInstance<SigningClientConfigurationLoader>(sp,[args]));
                services.AddSingleton<ISigningClientProvider<SigningClientConfiguration>, SigningClientProvider>();
                services.AddSingleton<SigningClientRunner<SigningClientConfiguration>>();
            })
            .Build();

        if (Environment.ExitCode != 0)
        {
            return;
        }

        await host.StartAsync();

        var loader = host.Services.GetRequiredService<SigningClientRunner<SigningClientConfiguration>>();
        await loader.RunAsync();
        await host.StopAsync();
    }
}
