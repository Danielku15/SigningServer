using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NLog;
using NLog.Targets;

namespace SigningServer.Client;

internal class Program
{
    private static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("usage: SigningServer.Client.exe [--config File] Source1 [Source2 Source3 ...]");
            return;
        }

        SetupLogging();

        var log = LogManager.GetCurrentClassLogger();

        string configFile = null;
        if (args.Length > 2)
        {
            if (args[0] == "--config")
            {
                configFile = args[1];
                args = args.Skip(2).ToArray();
            }
        }
        
        if (string.IsNullOrEmpty(configFile))
        {
            configFile = Path.Combine(AppContext.BaseDirectory,
                "config.json");
        }

        if (!File.Exists(configFile))
        {
            log.Fatal("Could not find config.json beside executable");
            return;
        }

        SigningClientConfiguration configuration;
        try
        {
            log.Info("Loading config");
            configuration =
                JsonSerializer.Deserialize<SigningClientConfiguration>(await File.ReadAllTextAsync(configFile))!;
            if (configuration.Retry == 0)
            {
                configuration.Retry = 3;
            }

            log.Info("Configuration loaded");
        }
        catch (Exception e)
        {
            log.Error(e, "Config could not be loaded");
            Environment.ExitCode = ErrorCodes.InvalidConfiguration;
            return;
        }

        SigningClient client;
        try
        {
            log.Info("Creating client");
            client = new SigningClient(configuration);
            await client.ConnectAsync();
            log.Info("connected to server");
        }
        catch (Exception e)
        {
            log.Error(e, "Could not create signing client");
            Environment.ExitCode = ErrorCodes.CommunicationError;
            return;
        }

        try
        {
            foreach (var arg in args)
            {
                await client.SignFileAsync(arg);
            }
        }
        catch (UnauthorizedAccessException)
        {
            Environment.ExitCode = ErrorCodes.Unauthorized;
        }
        catch (UnsupportedFileFormatException)
        {
            Environment.ExitCode = ErrorCodes.UnsupportedFileFormat;
        }
        catch (FileAlreadySignedException)
        {
            Environment.ExitCode = ErrorCodes.FileAlreadySigned;
        }
        catch (FileNotFoundException)
        {
            Environment.ExitCode = ErrorCodes.FileNotFound;
        }
        catch (Exception e)
        {
            log.Fatal(e, "Unexpected error happened");
            Environment.ExitCode = ErrorCodes.UnexpectedError;
        }
    }

    private static void SetupLogging()
    {
        if (File.Exists(Path.Combine(AppContext.BaseDirectory, "nlog.config")))
        {
            return;
        }

        var configuration = new NLog.Config.LoggingConfiguration();
        const string Format = "${longdate} ${level} - ${message} ${exception:format=ToString}";
        var console = new ColoredConsoleTarget("console") { Layout = Format };
        var debugger = new DebuggerTarget("debug") { Layout = Format };
        configuration.AddTarget(console);
        configuration.AddTarget(debugger);

        configuration.AddRule(LogLevel.Trace, LogLevel.Off, console);
        configuration.AddRule(LogLevel.Trace, LogLevel.Off, debugger);
        LogManager.Configuration = configuration;
        LogManager.ReconfigExistingLoggers();
    }
}

internal static class ErrorCodes
{
    public const int UnexpectedError = 1;
    public const int FileNotFound = 2;
    public const int FileAlreadySigned = 3;
    public const int UnsupportedFileFormat = 4;
    public const int Unauthorized = 5;
    public const int InvalidConfiguration = 6;

    public const int CommunicationError = 7;
    // public const int SecurityNegotiationFailed = 8; -> Phased out
}

public class SigningClientConfiguration
{
    public string SigningServer { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public bool OverwriteSignatures { get; set; }
    public bool IgnoreExistingSignatures { get; set; }
    public bool IgnoreUnsupportedFiles { get; set; }
    public int Timeout { get; set; }
    public string HashAlgorithm { get; set; }
    public int Retry { get; set; }
}
