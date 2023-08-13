using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NLog.Web;
using SigningServer.ClientCore;

namespace SigningServer.StandaloneClient;

internal static class Program
{
    private static async Task Main(string[] args)
    {
        if (args.Length == 0 || args.Any(a => a is "/?" or "--help" or "-?" or "-help" or "-h"))
        {
            Console.WriteLine("usage: SigningServer.Client.exe [options] [Source1 Source2 Source3 ...]");
            Console.WriteLine("options: ");

            Console.WriteLine("  --help, -h");
            Console.WriteLine("      Print this help.");
            
            Console.WriteLine("  --config File, -c File");
            Console.WriteLine("      The path to the config.json to use (overwrites any previously provided settings)");

            SigningClientConfiguration.PrintUsage(Console.Out);

            Console.WriteLine("exit codes: ");
            Console.WriteLine("   1 - unexpected error");
            Console.WriteLine("   2 - Specified source could not be found");
            Console.WriteLine(
                "   3 - Detected a file which is already signed and --fail-on-existing-signatures is set");
            Console.WriteLine("   4 - Detected an unsupported file format and --fail-on-unsupported-files is active");
            Console.WriteLine("   5 - Unauthorized, wrong username or password");
            Console.WriteLine("   6 - Client configuration invalid");
            Console.WriteLine("   7 - Communication error");

            return;
        }

        using var host = Host.CreateDefaultBuilder( /* No Args */)
            .ConfigureAppConfiguration(config =>
            {
                config.AddJsonFile("config.json", optional: true);
            })
            .ConfigureServices(services =>
            {
                services.AddSingleton<ISigningConfigurationLoader>(sp =>
                    ActivatorUtilities.CreateInstance<DefaultSigningConfigurationLoader>(sp,
                        new object[] { args }));
                services.AddSingleton<ISigningClientProvider<SigningClientConfiguration>, SigningClientProvider>();
                services.AddSingleton<SigningClientRunner>();
            })
            .UseNLog()
            .Build();

        await host.StartAsync();

        var loader = host.Services.GetRequiredService<SigningClientRunner>();
        await loader.RunAsync();
        await host.StopAsync();
    }
}
