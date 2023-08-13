using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SigningServer.Server.Configuration;

namespace SigningServer.Server.Util;

/// <summary>
/// This component ensures HSM devices stay unlocked.
/// There were issues in the past where SafeNet tokens suddenly disappeared
/// or were locked again, causing the signing to fail. Reloading the certificate
/// seems to resolve this issue.
/// </summary>
public sealed class HardwareCertificateUnlocker : IHostedService
{
    private readonly ILogger<HardwareCertificateUnlocker> _logger;
    private readonly ILogger<CertificateConfiguration> _certConfigLogger;
    private Timer? _refreshTimer;
    private readonly ConcurrentBag<CertificateConfiguration> _certificatesToRefresh;
    private readonly TimeSpan _refreshTime;

    public HardwareCertificateUnlocker(
        ILogger<HardwareCertificateUnlocker> logger,
        ILogger<CertificateConfiguration> certConfigLogger,
        SigningServerConfiguration configuration)
    {
        _logger = logger;
        _certConfigLogger = certConfigLogger;
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

    private void UnlockAllTokens(object? state)
    {
        foreach (var configuration in _certificatesToRefresh)
        {
            try
            {
                // null here on purpose so that the config does not register itself multiple times. 
                configuration.LoadCertificate(_certConfigLogger, null);
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
