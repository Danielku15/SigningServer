using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NLog;
using NLog.Config;
using NLog.Extensions.Logging;

namespace SigningServer.Test;

[TestClass]
public class AssemblyEvents
{
    internal static X509Certificate2 Certificate;
    internal static AsymmetricAlgorithm PrivateKey;
    private static ILogger<AssemblyEvents> _log;
    internal static ILoggerFactory LoggerProvider { get; set; }

    [AssemblyInitialize]
    public static void AssemblyInit(TestContext context)
    {
        LogManager.Configuration = new XmlLoggingConfiguration("NLog.config");
        LogManager.ReconfigExistingLoggers();
        
        LoggerProvider = new NLogLoggerFactory(new NLogLoggerProvider(new NLogProviderOptions()));
        _log = LoggerProvider.CreateLogger<AssemblyEvents>();
        
        var certificatePath = Path.Combine(UnitTestBase.ExecutionDirectory, "Certificates",
            "SigningServer.Test.pfx");
        var certificatePassword = "SigningServer";
           
        _log.LogInformation("Loading certificate");

        Certificate = new X509Certificate2(certificatePath, certificatePassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.PersistKeySet);
        PrivateKey = Certificate.GetECDsaPrivateKey() ??
                     Certificate.GetRSAPrivateKey() ??
                     ((AsymmetricAlgorithm)Certificate.GetDSAPrivateKey());
        _log.LogInformation("Certificate loaded");
    }


    [AssemblyCleanup]
    public static void AssemblyCleanup()
    {
        try
        {
            _log.LogInformation("Removeing test certificate from store");
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Remove(Certificate);
            store.Close();
            _log.LogInformation("Certificate removed");
        }
        catch (Exception e)
        {
            _log.LogError(e, "Failed to cleanup certificate from store");
        }
    }
}
