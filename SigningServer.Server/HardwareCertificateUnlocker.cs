using System;
using System.Collections.Concurrent;
using System.Threading;
using NLog;
using SigningServer.Server.Configuration;

namespace SigningServer.Server
{
    public sealed class HardwareCertificateUnlocker : IDisposable
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();
        
        private readonly Timer _refreshTimer;
        private readonly ConcurrentBag<CertificateConfiguration> _certificatesToRefresh; 

        public HardwareCertificateUnlocker(TimeSpan refreshTime)
        {
            _certificatesToRefresh = new ConcurrentBag<CertificateConfiguration>();
            _refreshTimer = new Timer(UnlockAllTokens, null, refreshTime, refreshTime);
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
                    Log.Error(e, "Failed to refresh certificate");
                }
            }
        }

        public void Dispose()
        {
            _refreshTimer?.Dispose();
        }

        public void RegisterForUpdate(CertificateConfiguration certificateConfiguration)
        {
            _certificatesToRefresh.Add(certificateConfiguration);
        }

    }
}