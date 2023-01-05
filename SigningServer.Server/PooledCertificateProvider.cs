using System;
using System.Collections.Concurrent;
using System.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using SigningServer.Server.Configuration;
using SigningServer.Server.Util;

namespace SigningServer.Server;

public class PooledCertificateProvider : ICertificateProvider
{
    private readonly SigningServerConfiguration _configuration;
    private readonly ObjectPoolProvider _objectPoolProvider;
    private readonly ILogger<PooledCertificateProvider> _logger;
    private readonly ILogger<CertificateConfiguration> _certConfigLogger;
    private readonly HardwareCertificateUnlocker _hardwareCertificateUnlocker;

    private readonly ConcurrentDictionary<string /*username*/, ObjectPool<CertificateConfiguration>>
        _certificatePools = new();

    public PooledCertificateProvider(
        SigningServerConfiguration configuration,
        ObjectPoolProvider objectPoolProvider,
        ILogger<PooledCertificateProvider> logger,
        ILogger<CertificateConfiguration> certConfigLogger,
        HardwareCertificateUnlocker hardwareCertificateUnlocker)
    {
        _configuration = configuration;
        _objectPoolProvider = objectPoolProvider;
        _logger = logger;
        _certConfigLogger = certConfigLogger;
        _hardwareCertificateUnlocker = hardwareCertificateUnlocker;
    }

    private class CertificateCloningObjectPolicy : PooledObjectPolicy<CertificateConfiguration>
    {
        private readonly ILogger _logger;
        private readonly CertificateConfiguration _baseConfiguration;
        private readonly ILogger<CertificateConfiguration> _certConfigLogger;
        private readonly HardwareCertificateUnlocker _hardwareCertificateUnlocker;

        public CertificateCloningObjectPolicy(
            ILogger logger,
            CertificateConfiguration baseConfiguration,
            ILogger<CertificateConfiguration> certConfigLogger,
            HardwareCertificateUnlocker hardwareCertificateUnlocker)
        {
            _logger = logger;
            _baseConfiguration = baseConfiguration;
            _certConfigLogger = certConfigLogger;
            _hardwareCertificateUnlocker = hardwareCertificateUnlocker;
        }

        public override CertificateConfiguration Create()
        {
            _logger.LogInformation($"Creating a new certificate instance for signing: {_baseConfiguration}");
            try
            {
                return _baseConfiguration.CloneForSigning(_certConfigLogger, _hardwareCertificateUnlocker);
            }
            catch (Exception e)
            {
                _logger.LogError(e, $"Failed to create a new certificate instance for signing: {_baseConfiguration}");
                throw;
            }
        }

        public override bool Return(CertificateConfiguration obj)
        {
            return true;
        }
    }

    public CertificateConfiguration Get(string username, string password)
    {
        CertificateConfiguration baseConfiguration;
        if (string.IsNullOrWhiteSpace(username))
        {
            baseConfiguration = _configuration.Certificates.FirstOrDefault(c => c.IsAnonymous);
            username = string.Empty;
        }
        else
        {
            baseConfiguration = _configuration.Certificates.FirstOrDefault(
                c => c.IsAuthorized(username, password));
        }

        if (baseConfiguration == null)
        {
            return null;
        }

        var pool = _certificatePools.GetOrAdd(username,
            _ => _objectPoolProvider.Create(new CertificateCloningObjectPolicy(_logger,
                baseConfiguration, _certConfigLogger,
                _hardwareCertificateUnlocker))
        );
        return pool.Get();
    }

    public void Return(string username, CertificateConfiguration certificateConfiguration)
    {
        if (certificateConfiguration == null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(username))
        {
            username = string.Empty;
        }

        _certificatePools[username].Return(certificateConfiguration);
    }

    public void Destroy(CertificateConfiguration certificateConfiguration)
    {
        if (certificateConfiguration == null)
        {
            return;
        }

        try
        {
            certificateConfiguration.Certificate.Dispose();
        }
        catch(Exception e)
        {
            _logger.LogInformation(e, "Error during disposing of certificate");
        }
        
        try
        {
            certificateConfiguration.PrivateKey.Dispose();
        }
        catch(Exception e)
        {
            _logger.LogInformation(e, "Error during disposing of PrivateKey");
        }
    }
}
