using System;
using System.IO;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.WindowsServices;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NLog.Web;
using SigningServer.Server.Configuration;
using SigningServer.Server.Util;
using SigningServer.Signing.Configuration;

namespace SigningServer.Server;

public class Program
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

        Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
        var host = CreateWebHostBuilder(args).Build();
        if (Environment.UserInteractive)
        {
            host.Run();
        }
        else
        {
            host.RunAsService();
        }
    }

    private static IWebHostBuilder CreateWebHostBuilder(string[] args)
    {
        // Workaround to load config
        var builder = WebHost.CreateDefaultBuilder(args);
        builder.Configure(_ => { });
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
            .UseKestrel(options =>
            {
                options.Limits.MaxRequestBufferSize = null;
                options.Limits.MaxRequestBodySize = null;
                options.Limits.MaxResponseBufferSize = null;
            })
            .UseStartup<Startup>();
    }
}
