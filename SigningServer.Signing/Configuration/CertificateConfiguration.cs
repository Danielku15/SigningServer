using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SigningServer.Signing.Configuration;

/// <summary>
/// Represents an access credentials which can be used to use a certificate.
/// </summary>
public class CertificateAccessCredentials
{
    public static readonly CertificateAccessCredentials? Anonymous = new();

    public string Username { get; set; } = "";
    public string Password { get; set; } = "";

    public string DisplayName => Username.Length > 0 ? Username : "Anonymous";
}

/// <summary>
/// A single certificate configuration.
/// </summary>
public class CertificateConfiguration
{
    /// <summary>
    /// A name of the certificate for identification (in logs and configuration).
    /// </summary>
    public string CertificateName { get; set; } = "";

    public string DisplayName
    {
        get
        {
            return !string.IsNullOrEmpty(CertificateName)
                ? CertificateName
                : Certificate?.SubjectName.Name ??
                  "missing-cert-name";
        }
    }

    /// <summary>
    /// A value indicating whether this certificate is used when no credentials are provided by the client..
    /// </summary>
    public bool IsAnonymous => Credentials.Length == 0 ||
                               Credentials.Any(
                                   t => string.IsNullOrEmpty(t.Username) && string.IsNullOrEmpty(t.Password));

    /// <summary>
    /// A list of access tokens which can be used to sign with this certificate.
    /// </summary>
    public CertificateAccessCredentials[] Credentials { get; set; } = Array.Empty<CertificateAccessCredentials>();

    /// <summary>
    /// Local Certificate from Certificate Store
    /// </summary>
    public LocalStoreCertificateConfiguration? LocalStore { get; set; }

    /// <summary>
    /// Azure specific configuration
    /// </summary>
    public AzureKeyVaultConfiguration? Azure { get; set; }

    /// <summary>
    /// Signing Server specific configuration
    /// </summary>
    public SigningServerApiConfiguration? SigningServer { get; set; }

    /// <summary>
    /// The loaded certificate.
    /// </summary>
    [JsonIgnore]
    public X509Certificate2? Certificate { get; set; }

    /// <summary>
    /// The loaded private key.
    /// </summary>
    [JsonIgnore]
    public AsymmetricAlgorithm? PrivateKey { get; set; }


    public async Task LoadCertificateAsync(ILogger logger, IHardwareCertificateUnlocker? unlocker)
    {
        // only do reloads if cert needs hardware unlock or certificate is not loaded at all
        if (string.IsNullOrEmpty(LocalStore?.TokenPin) && Certificate != null)
        {
            return;
        }

        Certificate?.Dispose();

        if (!string.IsNullOrEmpty(Azure?.KeyVaultUrl))
        {
            await Azure.LoadAsync(logger, this);
        }
        else if (LocalStore != null)
        {
            if (OperatingSystem.IsWindows())
            {
                LocalStore.Load(logger, this, unlocker);
            }
            else
            {
                throw new PlatformNotSupportedException("Local Store certificates can only be used on Windows");
            }
        }
        else if (SigningServer != null)
        {
            await SigningServer.LoadAsync(logger, this);
        }
        else
        {
            throw new InvalidConfigurationException(
                "There is a wrongly configured certificate in the configuration, no Azure or LocalStore configuration found");
        }
    }

    public CertificateAccessCredentials? IsAuthorized(string username, string? password)
    {
        return Credentials.FirstOrDefault(t =>
            string.Equals(t.Username, username, StringComparison.CurrentCultureIgnoreCase) && t.Password == password
        );
    }

    public override string ToString()
    {
        if (LocalStore?.Thumbprint != null)
        {
            return $"Name: {CertificateName}, Local: {LocalStore}";
        }

        if (Azure?.CertificateName != null)
        {
            return $"Name: {CertificateName}, Local: {Azure}";
        }

        return $"Name: {CertificateName}, Unknown certificate";
    }

    public async ValueTask<CertificateConfiguration> CloneForSigningAsync(ILogger<CertificateConfiguration> logger,
        IHardwareCertificateUnlocker unlocker)
    {
        var configuration = new CertificateConfiguration
        {
            CertificateName = CertificateName, Credentials = Credentials, LocalStore = LocalStore, Azure = Azure
        };

        if (LocalStore != null || Azure != null || SigningServer != null)
        {
            await configuration.LoadCertificateAsync(logger, unlocker);
        }
        else if (Certificate != null && PrivateKey != null && OperatingSystem.IsWindows())
        {
            // NOTE: This path is mainly needed for testing and rather not in production.
            configuration.Certificate = new X509Certificate2(Certificate);
            switch (PrivateKey)
            {
                case RSACng pk:
                    configuration.PrivateKey = new RSACng(pk.Key);
                    break;
                case DSACng pk:
                    configuration.PrivateKey = new DSACng(pk.Key);
                    break;
                case ECDsaCng pk:
                    configuration.PrivateKey = new ECDsaCng(pk.Key);
                    break;
                case RSACryptoServiceProvider pk:
                    var rsaCsp = new RSACryptoServiceProvider();
                    rsaCsp.ImportParameters(pk.ExportParameters(false));
                    configuration.PrivateKey = rsaCsp;
                    break;
                case DSACryptoServiceProvider pk:
                    var dsaCsp = new DSACryptoServiceProvider();
                    dsaCsp.ImportParameters(pk.ExportParameters(false));
                    configuration.PrivateKey = dsaCsp;
                    break;
                default:
                    throw new InvalidConfigurationException("Cannot clone private key");
            }
        }
        else
        {
            throw new InvalidConfigurationException("Cannot load certificate");
        }

        return configuration;
    }
}
