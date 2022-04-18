using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SigningServer.Server.Configuration;

namespace SigningServer.Server;

public sealed class HardwareCertificateUnlocker : IHostedService
{
    private readonly ILogger<HardwareCertificateUnlocker> _logger;
    private Timer _refreshTimer;
    private readonly ConcurrentBag<CertificateConfiguration> _certificatesToRefresh;
    private readonly TimeSpan _refreshTime;

    public HardwareCertificateUnlocker(ILogger<HardwareCertificateUnlocker> logger,
        SigningServerConfiguration configuration)
    {
        _logger = logger;
        _refreshTime = TimeSpan.FromSeconds(configuration.HardwareCertificateUnlockIntervalInSeconds);
        _certificatesToRefresh = new ConcurrentBag<CertificateConfiguration>();
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _refreshTimer = new Timer(UnlockAllTokens, null, _refreshTime, _refreshTime);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _refreshTimer?.Dispose();
        return Task.CompletedTask;
    }

    private void UnlockAllTokens(object state)
    {
        foreach (var configuration in _certificatesToRefresh)
        {
            try
            {
                // null here on purpose so that the config does not register itself multiple times. 
                configuration.LoadCertificate(null);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to refresh certificate");
            }
        }
    }

    public void RegisterForUpdate(CertificateConfiguration certificateConfiguration)
    {
        _certificatesToRefresh.Add(certificateConfiguration);
    }
}
