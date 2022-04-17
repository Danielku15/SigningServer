using System;
using CoreWCF.Configuration;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NLog.Web;
using SigningServer.Server.Configuration;

namespace SigningServer.Server;

class Program
{
    public static void Main(string[] args)
    {
        if (Environment.UserInteractive)
        {
            if (args.Length > 0)
            {
                switch (args[0])
                {
                    case "-encode":
                        Console.WriteLine("Original data: " + args[1]);
                        Console.WriteLine("Encrypted data: " + DataProtector.ProtectData(args[1]));
                        return;
                }
            }
        }
            
        var host = CreateWebHostBuilder(args).Build();
        host.Run();
    }

    private static IWebHostBuilder CreateWebHostBuilder(string[] args)
    {
        // Workaround to load config
        var builder = WebHost.CreateDefaultBuilder(args);
        var configuration = builder.Build().Services.GetRequiredService<IConfiguration>();
        var signingServerConfiguration = new SigningServerConfiguration();
        configuration.GetSection("SigningServer").Bind(signingServerConfiguration);

        return WebHost.CreateDefaultBuilder(args)
            .ConfigureServices(services =>
            {
                services.AddSingleton(signingServerConfiguration);
            })
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.SetMinimumLevel(LogLevel.Trace);
            })
            .UseNLog()
            .UseKestrel()
            .UseNetTcp(signingServerConfiguration.Port)
            .UseStartup<Startup>();
    }
}