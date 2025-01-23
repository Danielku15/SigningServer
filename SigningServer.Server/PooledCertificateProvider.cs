using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
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

        private ValueTask<CertificateConfiguration> CreateAsync()
        {
            _logger.LogInformation($"Creating a new certificate instance for signing: {_baseConfiguration}");
            try
            {
                return _baseConfiguration.CloneForSigningAsync(_certConfigLogger, _hardwareCertificateUnlocker);
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

        public ValueTask<CertificateConfiguration> GetAsync()
        {
            if (_pooledItems.TryDequeue(out var fromPool))
            {
                return ValueTask.FromResult(fromPool);
            }

            return CreateAsync();
        }
    }

    public ICertificateAccessor? Get(string? username, string? password)
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

        var certificateName = !string.IsNullOrEmpty(baseConfiguration.CertificateName)
            ? baseConfiguration.CertificateName
            : baseConfiguration.Username ?? "default";
        return new PooledCertificateAccessor(
            certificateName,
            new Lazy<ValueTask<CertificateConfiguration>>(() => GetWorkingFromPoolAsync(pool))
        );
    }

    private static readonly byte[] SignTestSha2Hash = ((Func<byte[]>)(() =>
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes("SignTest"));
    }))();

    private bool _hasNoWorkingCertificates;

    private async ValueTask<CertificateConfiguration> GetWorkingFromPoolAsync(CertificatePool pool)
    {
        var poolSize = pool.Size;
        var cert = await pool.GetAsync();

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
                cert = await pool.GetAsync();
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

    public async ValueTask ReturnAsync(string? username, ICertificateAccessor certificateConfiguration)
    {
        if (certificateConfiguration is not PooledCertificateAccessor { Configuration.IsValueCreated: true } accessor)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(username))
        {
            username = string.Empty;
        }

        _certificatePools[username].Return(await accessor.Configuration.Value);
    }

    public async ValueTask DestroyAsync(ICertificateAccessor? certificateConfiguration)
    {
        if (certificateConfiguration is not PooledCertificateAccessor { Configuration.IsValueCreated: true } accessor)
        {
            return;
        }

        Destroy(await accessor.Configuration.Value);
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

    private class PooledCertificateAccessor : ICertificateAccessor
    {
        public string CertificateName { get; }
        public Lazy<ValueTask<CertificateConfiguration>> Configuration { get; }

        public PooledCertificateAccessor(
            string certificateName,
            Lazy<ValueTask<CertificateConfiguration>> configuration)
        {
            CertificateName = certificateName;
            Configuration = configuration;
        }

        public ValueTask<CertificateConfiguration> UseCertificate()
        {
            return Configuration.Value;
        }
    }
}
