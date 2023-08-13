using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using SigningServer.Server.Configuration;
using SigningServer.Server.Util;
using SigningServer.Signing.Configuration;

namespace SigningServer.Server;

public class PooledCertificateProvider : ICertificateProvider
{
    private readonly SigningServerConfiguration _configuration;
    private readonly ILogger<PooledCertificateProvider> _logger;
    private readonly ILogger<CertificateConfiguration> _certConfigLogger;
    private readonly HardwareCertificateUnlocker _hardwareCertificateUnlocker;

    private readonly ConcurrentDictionary<string /*username*/, CertificatePool>
        _certificatePools = new();

    public PooledCertificateProvider(
        SigningServerConfiguration configuration,
        ILogger<PooledCertificateProvider> logger,
        ILogger<CertificateConfiguration> certConfigLogger,
        HardwareCertificateUnlocker hardwareCertificateUnlocker)
    {
        _configuration = configuration;
        _logger = logger;
        _certConfigLogger = certConfigLogger;
        _hardwareCertificateUnlocker = hardwareCertificateUnlocker;
    }

    private class CertificatePool
    {
        private readonly ILogger _logger;
        private readonly CertificateConfiguration _baseConfiguration;
        private readonly ILogger<CertificateConfiguration> _certConfigLogger;
        private readonly HardwareCertificateUnlocker _hardwareCertificateUnlocker;

        private readonly ConcurrentQueue<CertificateConfiguration>
            _pooledItems = new();

        public CertificatePool(
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

        public int Size => _pooledItems.Count;

        private CertificateConfiguration Create()
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

        public void Return(CertificateConfiguration obj)
        {
            _pooledItems.Enqueue(obj);
        }

        public CertificateConfiguration Get()
        {
            if (_pooledItems.TryDequeue(out var fromPool))
            {
                return fromPool;
            }

            return Create();
        }
    }

    public Lazy<CertificateConfiguration>? Get(string? username, string? password)
    {
        CertificateConfiguration? baseConfiguration;
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
            _ => new CertificatePool(_logger, baseConfiguration, _certConfigLogger, _hardwareCertificateUnlocker)
        );

        return new Lazy<CertificateConfiguration>(() => GetWorkingFromPool(pool));
    }

    private static readonly byte[] SignTestSha2Hash = ((Func<byte[]>)(() =>
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes("SignTest"));
    }))();

    private bool _hasNoWorkingCertificates;

    private CertificateConfiguration GetWorkingFromPool(CertificatePool pool)
    {
        var poolSize = pool.Size;
        var cert = pool.Get();

        // For some reason certain smartcard/HSM certificates can get broken over time and will
        // start reporting "Internal Errors" without further info what's happening. 
        // Due to that we do a preliminary check of the certificate here and drop any broken ones

        var certFunctional = false;
        Exception? lastException = null;
        for (var retry = 0; retry < poolSize + 1; retry++)
        {
            try
            {
                switch (cert.PrivateKey)
                {
                    case DSA dsa:
                        dsa.CreateSignature(SignTestSha2Hash);
                        break;
                    case ECDsa ecdsa:
                        ecdsa.SignHash(SignTestSha2Hash);
                        break;
                    case RSA rsa:
                        rsa.SignHash(SignTestSha2Hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }

                certFunctional = true;
            }
            catch (CryptographicException e)
            {
                lastException = e;
                // private key not functional, try next cett
                Destroy(cert);
                cert = pool.Get();
                certFunctional = false;
            }
        }

        if (!certFunctional)
        {
            pool.Return(cert);
            _hasNoWorkingCertificates = true;
            _logger.LogCritical($"Could not find working certificate in pool after {poolSize} attempts");
            throw lastException ?? new CryptographicException("Could not find working certificate");
        }

        if (_hasNoWorkingCertificates)
        {
            _logger.LogInformation($"Found working certificate again after once all were not working");
            _hasNoWorkingCertificates = false;
        }

        return cert;
    }

    public void Return(string? username, Lazy<CertificateConfiguration> certificateConfiguration)
    {
        if (certificateConfiguration is not { IsValueCreated: true })
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(username))
        {
            username = string.Empty;
        }

        _certificatePools[username].Return(certificateConfiguration.Value);
    }

    public void Destroy(Lazy<CertificateConfiguration>? certificateConfiguration)
    {
        if (certificateConfiguration is not { IsValueCreated: true })
        {
            return;
        }

        Destroy(certificateConfiguration.Value);
    }

    private void Destroy(CertificateConfiguration certificateConfiguration)
    {
        try
        {
            certificateConfiguration.Certificate?.Dispose();
        }
        catch (Exception e)
        {
            _logger.LogInformation(e, "Error during disposing of certificate");
        }

        try
        {
            certificateConfiguration.PrivateKey?.Dispose();
        }
        catch (Exception e)
        {
            _logger.LogInformation(e, "Error during disposing of PrivateKey");
        }
    }
}
