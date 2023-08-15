using System.IO;
using Microsoft.Extensions.Logging;
using SigningServer.ClientCore;

namespace SigningServer.Client;

/// <summary>
/// Represents the signing client configuration.
/// </summary>
public class SigningClientConfiguration : SigningClientConfigurationBase
{
    /// <summary>
    /// The url to the signing server.
    /// </summary>
    public string SigningServer { get; set; } = string.Empty;

    /// <summary>
    /// The username for authentication and cerificate selection.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// The password for authentication and certificate selection.
    /// </summary>
    public string Password { get; set; } = string.Empty;

    public new static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine("  --server Server, -s Server");
        writer.WriteLine("      The URL to the Signing Server to use");
        writer.WriteLine("      Config.json Key: \"SigningServer\": \"value\"");

        writer.WriteLine("  --username [username], -u [username]");
        writer.WriteLine("      The username to use for authentication and certificate selection on the server");
        writer.WriteLine("      Config.json Key: \"Username\": \"value\"");

        writer.WriteLine("  --password [password], -p [password]");
        writer.WriteLine("      The password to use for authentication and certificate selection on the server");
        writer.WriteLine("      Config.json Key: \"Password\": \"value\"");

        SigningClientConfigurationBase.PrintUsage(writer);
    }

    protected override bool HandleArg(ILogger log, string arg, string[] args, ref int i)
    {
        switch (arg)
        {
            case "-s":
            case "--server":
                if (i + 1 < args.Length)
                {
                    i++;
                    SigningServer = args[i];
                }
                else
                {
                    log.LogError("Config could not be loaded: No server value provided");
                    return false;
                }

                return true;
            case "-u":
            case "--username":
                if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                {
                    i++;
                    Username = args[i];
                }
                else
                {
                    Username = "";
                }

                return true;
            case "-p":
            case "--password":
                if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                {
                    i++;
                    Password = args[i];
                }
                else
                {
                    Password = "";
                }

                return true;
        }

        return base.HandleArg(log, arg, args, ref i);
    }
}
