using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SigningServer.ClientCore;
using SigningServer.Signing.Configuration;

namespace SigningServer.StandaloneClient;

public enum ServerType
{
    LocalStore,
    Azure,
    SigningServer
}

/// <summary>
/// Represents the signing client configuration.
/// </summary>
public class StandaloneSigningClientConfiguration : SigningClientConfigurationBase
{
    public ServerType ServerType { get; set; }

    /// <summary>
    /// A RFC-3161 compliant timestamping server which should be used.
    /// </summary>
    public string TimestampServer { get; set; } = string.Empty;

    /// <summary>
    /// The directory where the client will put temporarily the files during signing.
    /// </summary>
    public string WorkingDirectory { get; set; } = string.Empty;

    /// <summary>
    /// The certificate configuration to use for signing.
    /// </summary>
    public CertificateConfiguration Server { get; set; } = new();
    
    public new static void PrintUsage(TextWriter writer)
    {
        SigningClientConfigurationBase.PrintUsage(writer);

        writer.WriteLine("  --server-type ServerType");
        writer.WriteLine("      The type of server to use (specify settings accordingly)");
        writer.WriteLine("      Config.json Key: \"ServerType\": \"value\"");
        writer.WriteLine();

        writer.WriteLine("  ServerType=SigningServer");
        writer.WriteLine("  Performs the Cryptographic Operations on a Signing Server API");
        writer.WriteLine("      --server-url Server");
        writer.WriteLine("          The URL to the Signing Server to use");
        writer.WriteLine("          Config.json Key: \"Server.SigningServer.SigningServer\": \"value\"");

        writer.WriteLine("      --server-username [username]");
        writer.WriteLine("          The username to use for authentication and certificate selection on the server");
        writer.WriteLine("          Config.json Key: \"Server.SigningServer.Username\": \"value\"");

        writer.WriteLine("      --server-password [password]");
        writer.WriteLine("          The password to use for authentication and certificate selection on the server");
        writer.WriteLine("          Config.json Key: \"Server.SigningServer.Password\": \"value\"");
        writer.WriteLine();

        writer.WriteLine("  ServerType=AzureKeyVault");
        writer.WriteLine("  Performs the Cryptographic Operations on an Azure Key Vault");
        writer.WriteLine("      --akv-url KeyVaultUrl");
        writer.WriteLine("          The url to the azure keyvault like https://weu-000-keyvaultname.vault.azure.net/");
        writer.WriteLine("          Config.json Key: \"Server.Azure.KeyVaultUrl\": \"value\"");
        writer.WriteLine("      --akv-tenant-id TenantId");
        writer.WriteLine("          The ID of the tenant for accessing the keyvault via Service Principle.");
        writer.WriteLine("          (If not using Managed Identities)");
        writer.WriteLine("          Config.json Key: \"Server.Azure.TenantId\": \"value\"");
        writer.WriteLine("      --akv-client-id ClientId");
        writer.WriteLine("          The ID of the client for accessing the keyvault via Service Principle.");
        writer.WriteLine("          (If not using Managed Identities)");
        writer.WriteLine("          Config.json Key: \"Server.Azure.ClientId\": \"value\"");
        writer.WriteLine("      --akv-client-secret ClientSecret");
        writer.WriteLine("          The secret of the client for accessing the keyvault via Service Principle.");
        writer.WriteLine("          (If not using Managed Identities)");
        writer.WriteLine("          Config.json Key: \"Server.Azure.ClientSecret\": \"value\"");
        writer.WriteLine("      --akv-managed-identity");
        writer.WriteLine("          Whether to attempt using a managed identity for authentication.");
        writer.WriteLine("          Config.json Key: \"Server.Azure.ManagedIdentity\": true");

        writer.WriteLine();

        writer.WriteLine("  ServerType=LocalStore");
        writer.WriteLine(
            "  Performs the Cryptographic Operations locally using a Certificate from the Windows Certificate Store");
        writer.WriteLine("      --store-name StoreName");
        writer.WriteLine("          The name of the certificate store to access.");
        writer.WriteLine(
            "          (AddressBook, AuthRoot, CertificateAuthority, Disallowed, My, Root, TrustedPeople, TrustedPublisher)");
        writer.WriteLine("          Config.json Key: \"Server.LocalStore.StoreName\": \"value\"");
        writer.WriteLine("      --store-location StoreLocation");
        writer.WriteLine("          The location of the store.");
        writer.WriteLine("          (CurrentUser, LocalMachine)");
        writer.WriteLine("          Config.json Key: \"Server.LocalStore.StoreLocation\": \"value\"");
        writer.WriteLine("      --store-thumbprint Thumbprint");
        writer.WriteLine("          The thumbprint of the certificate to load.");
        writer.WriteLine("          Config.json Key: \"Server.LocalStore.ThumbPrint\": \"value\"");
        writer.WriteLine();
    }

    public override bool FillFromArgs(string[] args, ILogger log)
    {
        Server.SigningServer = new SigningServerApiConfiguration();
        Server.Azure = new AzureKeyVaultConfiguration();
        Server.LocalStore = new LocalStoreCertificateConfiguration();

        var result = base.FillFromArgs(args, log);

        switch (ServerType)
        {
            case ServerType.SigningServer:
                Server.Azure = null;
                Server.LocalStore = null;
                Server.SigningServer.Timeout = Timeout;
                break;
            case ServerType.Azure:
                Server.SigningServer = null;
                Server.LocalStore = null;
                break;
            case ServerType.LocalStore:
                Server.SigningServer = null;
                Server.Azure = null;
                break;
        }

        return result;
    }

    protected override bool HandleArg(ILogger log, string arg, string[] args, ref int i)
    {
        switch (arg)
        {
            case "--server-type":
                if (i + 2 < args.Length)
                {
                    i++;
                    if (!Enum.TryParse(typeof(ServerType), args[i], true, out var p) ||
                        p is not ServerType contentType)
                    {
                        log.LogError("Config could not be loaded: Invalid server type");
                        return false;
                    }

                    ServerType = contentType;
                }
                else
                {
                    log.LogError("Config could not be loaded: No server type value provided");
                    return false;
                }

                return true;
        }

        if (HandleSigningServerArg(log, arg, args, ref i))
        {
            return true;
        }

        if (HandleAzureArg(log, arg, args, ref i))
        {
            return true;
        }

        if (HandleLocalStoreArg(log, arg, args, ref i))
        {
            return true;
        }

        return base.HandleArg(log, arg, args, ref i);
    }

    private bool HandleLocalStoreArg(ILogger log, string arg, string[] args, ref int i)
    {
        switch (arg)
        {
            case "--store-name":
                if (i + 1 < args.Length)
                {
                    i++;
                    Server.LocalStore!.StoreName = args[i];
                }
                else
                {
                    log.LogError("Config could not be loaded: No Local Store Name value provided");
                    return false;
                }

                return true;
            case "--store-location":
                if (i + 1 < args.Length)
                {
                    i++;
                    Server.LocalStore!.StoreLocation = args[i];
                }
                else
                {
                    log.LogError("Config could not be loaded: No Local Store Location value provided");
                    return false;
                }

                return true;
            case "--store-thumbprint":
                if (i + 1 < args.Length)
                {
                    i++;
                    Server.LocalStore!.Thumbprint = args[i];
                }
                else
                {
                    log.LogError("Config could not be loaded: No Local Store Thumbprint value provided");
                    return false;
                }

                return true;
        }

        return false;
    }

    private bool HandleAzureArg(ILogger log, string arg, string[] args, ref int i)
    {
        switch (arg)
        {
            case "--akv-url":
                if (i + 1 < args.Length)
                {
                    i++;
                    Server.Azure!.KeyVaultUrl = args[i];
                }
                else
                {
                    log.LogError("Config could not be loaded: No Azure Key Vault URL value provided");
                    return false;
                }

                return true;
            case "--akv-tenant-id":
                if (i + 1 < args.Length)
                {
                    i++;
                    Server.Azure!.TenantId = args[i];
                }
                else
                {
                    log.LogError("Config could not be loaded: No Azure Key Vault Tenant ID value provided");
                    return false;
                }

                return true;
            case "--akv-client-id":
                if (i + 1 < args.Length)
                {
                    i++;
                    Server.Azure!.ClientId = args[i];
                }
                else
                {
                    log.LogError("Config could not be loaded: No Azure Key Vault Client ID value provided");
                    return false;
                }

                return true;
            case "--akv-client-secret":
                if (i + 1 < args.Length)
                {
                    i++;
                    Server.Azure!.ClientSecret = args[i];
                }
                else
                {
                    log.LogError("Config could not be loaded: No Azure Key Vault Client Secret value provided");
                    return false;
                }

                return true;
            case "--akv-managed-identity":
                Server.Azure!.ManagedIdentity = true;
                return true;
        }

        return false;
    }

    private bool HandleSigningServerArg(ILogger log, string arg, string[] args, ref int i)
    {
        switch (arg)
        {
            case "--server-url":
                if (i + 1 < args.Length)
                {
                    i++;
                    Server.SigningServer!.SigningServer = args[i];
                }
                else
                {
                    log.LogError("Config could not be loaded: No server value provided");
                    return false;
                }

                return true;
            case "--server-username":
                if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                {
                    i++;
                    Server.SigningServer!.Username = args[i];
                }
                else
                {
                    Server.SigningServer!.Username = "";
                }

                return true;
            case "--server-password":
                if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                {
                    i++;
                    Server.SigningServer!.Password = args[i];
                }
                else
                {
                    Server.SigningServer!.Password = "";
                }

                return true;
        }

        return false;
    }
}
