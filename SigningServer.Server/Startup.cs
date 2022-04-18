using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SigningServer.Android.Collections;
using SigningServer.Server.Configuration;
using SigningServer.Server.SigningTool;
using SigningServer.Server.Util;

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
            ValidateConfiguration(logger, certConfigurationLogger, unlocker);
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

    private void ValidateConfiguration(ILogger<Startup> logger,
        ILogger<CertificateConfiguration> certConfigurationLogger,
        HardwareCertificateUnlocker unlocker)
    {
        logger.LogInformation("Validating configuration");
        var list = new List<CertificateConfiguration>();
        if (_configuration.Certificates != null)
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
                    certificateConfiguration.LoadCertificate(certConfigurationLogger, unlocker);
                    list.Add(certificateConfiguration);
                }
                catch (Exception e)
                {
                    logger.LogError(e, $"Certificate loading failed: {e.Message}");
                }
            }
        }

        if (list.Count == 0)
        {
            throw new InvalidConfigurationException(InvalidConfigurationException.NoValidCertificatesMessage);
        }

        _configuration.Certificates = list.ToArray();
        logger.LogInformation("Certificates loaded: {0}", list.Count);
    }
}
