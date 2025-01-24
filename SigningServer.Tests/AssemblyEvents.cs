using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NLog;
using NLog.Extensions.Logging;
using NLog.Web;
using NUnit.Framework;

namespace SigningServer.Test;

[SetUpFixture]
public class AssemblyEvents
{
    internal static Lazy<ValueTask<X509Certificate2>> Certificate = null!;
    internal static Lazy<ValueTask<AsymmetricAlgorithm>> PrivateKey = null!;
    private static ILogger<AssemblyEvents> _log = null!;
    internal static ILoggerFactory LoggerProvider { get; private set; } = null!;

    [OneTimeSetUp]
    public void AssemblyInit()
    {
        LogManager.Setup().LoadConfigurationFromAppSettings();
        LogManager.ReconfigExistingLoggers();

        LoggerProvider = new NLogLoggerFactory(new NLogLoggerProvider(new NLogProviderOptions()));
        _log = LoggerProvider.CreateLogger<AssemblyEvents>();

        var certificatePath = Path.Combine(UnitTestBase.ExecutionDirectory, "Certificates",
            "SigningServer.Test.pfx");
        var certificatePassword = "SigningServer";

        _log.LogInformation("Loading certificate");

        var cert = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, certificatePassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.PersistKeySet);
        Certificate = new Lazy<ValueTask<X509Certificate2>>(ValueTask.FromResult(cert));
        PrivateKey = new Lazy<ValueTask<AsymmetricAlgorithm>>(ValueTask.FromResult(cert.GetECDsaPrivateKey() ??
                                                              cert.GetRSAPrivateKey() ??
                                                              (AsymmetricAlgorithm)cert.GetDSAPrivateKey()!));
        _log.LogInformation("Certificate loaded");
    }


    [OneTimeTearDown]
    public async Task AssemblyCleanup()
    {
        try
        {
            _log.LogInformation("Removeing test certificate from store");
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Remove(await Certificate.Value);
            store.Close();
            _log.LogInformation("Certificate removed");
        }
        catch (Exception e)
        {
            _log.LogError(e, "Failed to cleanup certificate from store");
        }
    }
}
