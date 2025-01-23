using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SigningServer.Android.Collections;
using SigningServer.Server.Configuration;
using SigningServer.Server.Util;
using SigningServer.Signing;
using SigningServer.Signing.Configuration;

namespace SigningServer.Server;

public class Startup
{
    private readonly SigningServerConfiguration _configuration;

    public Startup(SigningServerConfiguration configuration)
    {
        _configuration = configuration;
        configuration.TimestampServer ??= "";
        configuration.Sha1TimestampServer ??= configuration.TimestampServer ?? "";
        configuration.WorkingDirectory ??= configuration.WorkingDirectory ?? ""; 
        configuration.HardwareCertificateUnlockIntervalInSeconds =
            configuration.HardwareCertificateUnlockIntervalInSeconds > 0
                ? configuration.HardwareCertificateUnlockIntervalInSeconds
                : 60 * 60;
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton<HardwareCertificateUnlocker>();
        services.AddTransient<IHostedService>(sp => sp.GetRequiredService<HardwareCertificateUnlocker>());
        services.AddSingleton<ISigningToolProvider, DefaultSigningToolProvider>();
        services.AddSingleton<IHashSigningTool, ManagedHashSigningTool>();
        services.TryAddSingleton<ISigningRequestTracker, DiskPersistingSigningRequestTracker>();
        services.AddSingleton<ICertificateProvider, PooledCertificateProvider>();
        services.Configure<FormOptions>(x =>
        {
            x.ValueLengthLimit = int.MaxValue;
            x.MultipartBodyLengthLimit = long.MaxValue;
        });

        services.AddControllers();
        services.AddEndpointsApiExplorer();
        services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.SetIsOriginAllowed(_ => true)
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials();
            });
        });
    }

    public void Configure(IApplicationBuilder app,
        ILogger<Startup> logger,
        ILogger<CertificateConfiguration> certConfigurationLogger,
        HardwareCertificateUnlocker unlocker,
        IHostApplicationLifetime lifetime)
    {
        lifetime.ApplicationStarted.Register(() =>
        {
            ValidateConfigurationAsync(logger, certConfigurationLogger, unlocker).GetAwaiter().GetResult();
            PrepareWorkingDirectory(logger);
        });

        app.UseCors();
        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }

    private void PrepareWorkingDirectory(ILogger<Startup> logger)
    {
        try
        {
            if (Directory.Exists(_configuration.WorkingDirectory))
            {
                logger.LogInformation("Working directory exists, cleaning");
                Directory.Delete(_configuration.WorkingDirectory, true);
            }

            Directory.CreateDirectory(_configuration.WorkingDirectory);
            logger.LogInformation("Working directory created");
        }
        catch (Exception e)
        {
            throw new InvalidConfigurationException(
                InvalidConfigurationException.CreateWorkingDirectoryFailedMessage, e);
        }

        logger.LogInformation("Working directory: {0}", _configuration.WorkingDirectory);
    }

    private async Task ValidateConfigurationAsync(ILogger<Startup> logger,
        ILogger<CertificateConfiguration> certConfigurationLogger,
        HardwareCertificateUnlocker unlocker)
    {
        logger.LogInformation("Validating configuration");
        var list = new List<CertificateConfiguration>();
        if (_configuration.Certificates is { Length: > 0 })
        {
            foreach (var certificateConfiguration in _configuration.Certificates)
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
            throw new InvalidConfigurationException(InvalidConfigurationException.NoValidCertificatesMessage);
        }

        _configuration.Certificates = list.ToArray();
        logger.LogInformation("Certificates loaded: {0}", list.Count);
    }
}
