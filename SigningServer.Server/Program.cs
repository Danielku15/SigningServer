using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.StaticWebAssets;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using NLog;
using NLog.Config;
using NLog.Extensions.Logging;
using NLog.Targets;
using NLog.Web;
using SigningServer.Android.Collections;
using SigningServer.Server.Configuration;
using SigningServer.Server.Dtos;
using SigningServer.Server.Util;
using SigningServer.Signing;
using SigningServer.Signing.Configuration;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace SigningServer.Server;

public class Program
{
    public static async Task Main(string[] args)
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

        var builder = WebApplication.CreateBuilder(args);

        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Limits.MaxRequestBodySize = null;
        });

        builder.Logging.ClearProviders();
        builder.Logging.AddNLogWeb();
        
        builder.Services.AddSingleton<SigningServerConfiguration>(_ =>
        {
            var signingServerConfiguration = new SigningServerConfiguration();
            builder.Configuration.GetSection("SigningServer").Bind(signingServerConfiguration);

            signingServerConfiguration.HardwareCertificateUnlockIntervalInSeconds =
                signingServerConfiguration.HardwareCertificateUnlockIntervalInSeconds > 0
                    ? signingServerConfiguration.HardwareCertificateUnlockIntervalInSeconds
                    : 60 * 60;

            return signingServerConfiguration;
        });
        builder.Services.AddControllers();

        builder.Services.AddSingleton<IUsageReportProvider, UsageReportProvider>();
        builder.Services.AddSingleton<HardwareCertificateUnlocker>();
        builder.Services.AddTransient<IHostedService>(sp => sp.GetRequiredService<HardwareCertificateUnlocker>());
        builder.Services.AddSingleton<ISigningToolProvider, DefaultSigningToolProvider>();
        builder.Services.AddSingleton<IHashSigningTool, ManagedHashSigningTool>();
        builder.Services.Configure<SystemInfo>(builder.Configuration.GetSection(SystemInfo.BaseKey));
        builder.Services.TryAddSingleton<ISigningRequestTracker, DiskPersistingSigningRequestTracker>();
        builder.Services.AddSingleton<ICertificateProvider>(sp =>
        {
            var config = sp.GetRequiredService<SigningServerConfiguration>();
            var logger = sp.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Will use certificate pooling: {0}", config.UseCertificatePooling);
            
            return config.UseCertificatePooling
                ? ActivatorUtilities.CreateInstance<PooledCertificateProvider>(sp)
                : ActivatorUtilities.CreateInstance<NonPooledCertificateProvider>(sp);
        });

        builder.Services.Configure<FormOptions>(x =>
        {
            x.ValueLengthLimit = int.MaxValue;
            x.MultipartBodyLengthLimit = long.MaxValue;
        });

        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.SetIsOriginAllowed(_ => true)
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials();
            });
        });

        if (WindowsServiceHelpers.IsWindowsService())
        {
            builder.Services.AddSingleton<IHostLifetime, WindowsServiceLifetime>();
        }
        
#if DEBUG
            StaticWebAssetsLoader.UseStaticWebAssets(builder.Environment, builder.Configuration);
#endif

        var app = builder.Build();

        var logger = app.Services.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("Starting SigningServer {version}", SystemInfo.ApplicationVersion);

        var signingServerConfiguration = app.Services.GetRequiredService<SigningServerConfiguration>();
        var unlocker = app.Services.GetRequiredService<HardwareCertificateUnlocker>();
        var certConfigurationLogger = app.Services.GetRequiredService<ILogger<CertificateConfiguration>>();
        await ValidateConfigurationAsync(logger, certConfigurationLogger, unlocker, signingServerConfiguration);
        PrepareWorkingDirectory(logger, signingServerConfiguration);

        app.UseCors();
        app.UseHttpsRedirection();
        app.UseRouting();
        
        app.MapStaticAssets();

        app.MapControllers();

        app.MapFallbackToFile("/", "index.html");

        await app.RunAsync();
    }

    private static async Task ValidateConfigurationAsync(ILogger logger,
        ILogger<CertificateConfiguration> certConfigurationLogger,
        HardwareCertificateUnlocker unlocker,
        SigningServerConfiguration configuration)
    {
        logger.LogInformation("Validating configuration");
        var list = new List<CertificateConfiguration>();
        if (configuration.Certificates is { Length: > 0 })
        {
            foreach (var certificateConfiguration in configuration.Certificates)
            {
                if (certificateConfiguration.Certificate != null)
                {
                    list.Add(certificateConfiguration);
                    continue;
                }

                try
                {
                    logger.LogInformation("Loading certificate '{certificateConfiguration}'", certificateConfiguration);
                    await certificateConfiguration.LoadCertificateAsync(certConfigurationLogger, unlocker);
                    list.Add(certificateConfiguration);
                }
                catch (Exception e)
                {
                    logger.LogError(e, $"Certificate loading failed: {e.Message}");
                }
            }
        }
        else
        {
            logger.LogError("No certificates configured in appsettings");
        }

        if (list.Count == 0)
        {
            // throw new InvalidConfigurationException(InvalidConfigurationException.NoValidCertificatesMessage);
        }

        configuration.Certificates = list.ToArray();
        logger.LogInformation("Certificates loaded: {0}", list.Count);
    }


    private static void PrepareWorkingDirectory(ILogger logger, SigningServerConfiguration configuration)
    {
        try
        {
            if (Directory.Exists(configuration.WorkingDirectory))
            {
                logger.LogInformation("Working directory exists, cleaning");
                Directory.Delete(configuration.WorkingDirectory, true);
            }

            Directory.CreateDirectory(configuration.WorkingDirectory);
            logger.LogInformation("Working directory created");
        }
        catch (Exception e)
        {
            throw new InvalidConfigurationException(
                InvalidConfigurationException.CreateWorkingDirectoryFailedMessage, e);
        }

        logger.LogInformation("Working directory: {0}", configuration.WorkingDirectory);
    }
}
