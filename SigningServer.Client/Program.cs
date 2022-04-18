using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using NLog;
using NLog.Targets;

namespace SigningServer.Client;

internal class Program
{
    private static async Task Main(string[] args)
    {
        if (args.Length == 0 || args.Any(a => a is "/?" or "--help" or "-?" or "-help" or "-h"))
        {
            Console.WriteLine("usage: SigningServer.Client.exe [options] [Source1 Source2 Source3 ...]");
            Console.WriteLine("options: ");

            Console.WriteLine("  --help, -h");
            Console.WriteLine("      Print this help.");

            Console.WriteLine("  --config File, -c File");
            Console.WriteLine("      The path to the config.json to use (overwrites any previously provided settings)");

            Console.WriteLine("  --server Server, -s Server");
            Console.WriteLine("      The URL to the Signing Server to use");
            Console.WriteLine("      Config.json Key: \"SigningServer\": \"value\"");

            Console.WriteLine("  --username [username], -u [username]");
            Console.WriteLine("      The username to use for authentication and certificate selection on the server");
            Console.WriteLine("      Config.json Key: \"Username\": \"value\"");

            Console.WriteLine("  --password [password], -p [password]");
            Console.WriteLine("      The password to use for authentication and certificate selection on the server");
            Console.WriteLine("      Config.json Key: \"Password\": \"value\"");

            Console.WriteLine("  --hash-algorithm [algorithm], -h [algorithm]");
            Console.WriteLine("      The Hash Algorithm to use for signing (empty for default)");
            Console.WriteLine("      Config.json Key: \"HashAlgorithm\": \"value\"");

            Console.WriteLine("  --overwrite-signatures, -os");
            Console.WriteLine("      Enable overwriting of existing signatures");
            Console.WriteLine("      Config.json Key: \"OverwriteSignatures\": true");

            Console.WriteLine("  --keep-signatures, -ks");
            Console.WriteLine("      Disable overwriting of existing signatures");
            Console.WriteLine("      Config.json Key: \"OverwriteSignatures\": false");

            Console.WriteLine("  --ignore-existing-signatures, -is");
            Console.WriteLine("      Ignore existing signatures");
            Console.WriteLine("      Config.json Key: \"IgnoreExistingSignatures\": true");

            Console.WriteLine("  --fail-on-existing-signatures, -fs");
            Console.WriteLine("      Whether to fail with existing signatures");
            Console.WriteLine("      Config.json Key: \"IgnoreExistingSignatures\": false");

            Console.WriteLine("  --ignore-unsupported-files, -iu");
            Console.WriteLine("      Whether to ignore unsupported file formats");
            Console.WriteLine("      Config.json Key: \"IgnoreUnsupportedFiles\": true");

            Console.WriteLine("  --fail-on-unsupported-files, -fu");
            Console.WriteLine("      Whether to fail when unsupported file formats");
            Console.WriteLine("      Config.json Key: \"IgnoreUnsupportedFiles\": false");

            Console.WriteLine("  --timeout Timeout, -t Timeout");
            Console.WriteLine("      Configures the timeout in seconds before failing the signing operations.");
            Console.WriteLine("      Config.json Key: \"IgnoreUnsupportedFiles\": 300");

            Console.WriteLine("  --retries Retries, -re Retries");
            Console.WriteLine(
                "      The number of retries to attempt on potentially recoverable errors (e.g. timeouts).");
            Console.WriteLine("      Config.json Key: \"Retry\": 3");

            Console.WriteLine("  --parallel [NumberOfThreads], -pa [NumberOfThreads]");
            Console.WriteLine("      The number of parallel signing operations the client should perform.");
            Console.WriteLine("      Might be reduced based on the server configuration.");
            Console.WriteLine("      Leave value empty (or null in config.json) for auto detection.");
            Console.WriteLine("      Config.json Key: \"Parallel\": 4");

            Console.WriteLine();

            Console.WriteLine("sources: ");
            Console.WriteLine("   Can be any single file or a full directory (recursive) to sign.");
            Console.WriteLine("   For directories only known supported files are considered.");
            Console.WriteLine();

            Console.WriteLine("exit codes: ");
            Console.WriteLine("   1 - unexpected error");
            Console.WriteLine("   2 - Specified source could not be found");
            Console.WriteLine(
                "   3 - Detected a file which is already signed and --fail-on-existing-signatures is set");
            Console.WriteLine("   4 - Detected an unsupported file format and --fail-on-unsupported-files is active");
            Console.WriteLine("   5 - Unauthorized, wrong username or password");
            Console.WriteLine("   6 - Client configuration invalid");
            Console.WriteLine("   7 - Communication error");

            return;
        }

        SetupLogging();

        var log = LogManager.GetCurrentClassLogger();
        var configuration = await LoadConfiguration(log, args);
        if (configuration == null)
        {
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
            await client.SignFilesAsync();
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
        catch (IOException)
        {
            Environment.ExitCode = ErrorCodes.CommunicationError;
        }
        catch (HttpRequestException)
        {
            Environment.ExitCode = ErrorCodes.CommunicationError;
        }
        catch (OperationCanceledException)
        {
            Environment.ExitCode = ErrorCodes.CommunicationError;
        }
        catch (Exception e)
        {
            log.Fatal(e, "Unexpected error happened");
            Environment.ExitCode = ErrorCodes.UnexpectedError;
        }
    }

    private static async Task<SigningClientConfiguration> LoadConfiguration(ILogger log, string[] args)
    {
        var configuration = await LoadDefaultConfigurationAsync(log);
        if (configuration == null)
        {
            return null;
        }

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("-"))
            {
                switch (arg.ToLowerInvariant())
                {
                    case "-c":
                    case "--config":
                        if (i + 1 < args.Length)
                        {
                            try
                            {
                                log.Info("Loading config");
                                configuration =
                                    JsonSerializer.Deserialize<SigningClientConfiguration>(
                                        await File.ReadAllTextAsync(args[i + 1]))!;
                                log.Info("Configuration loaded");
                            }
                            catch (Exception e)
                            {
                                log.Error(e, "Config could not be loaded");
                                Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                                return null;
                            }

                            i++;
                        }
                        else
                        {
                            log.Error("Config could not be loaded: No filename provided");
                            Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                            return null;
                        }

                        break;
                    case "-s":
                    case "--server":
                        if (i + 1 < args.Length)
                        {
                            i++;
                            configuration.SigningServer = args[i];
                        }
                        else
                        {
                            log.Error("Config could not be loaded: No server value provided");
                            Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                            return null;
                        }

                        break;
                    case "-u":
                    case "--username":
                        if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                        {
                            i++;
                            configuration.Username = args[i];
                        }
                        else
                        {
                            configuration.Username = "";
                        }

                        break;
                    case "-p":
                    case "--password":
                        if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                        {
                            i++;
                            configuration.Password = args[i];
                        }
                        else
                        {
                            configuration.Password = "";
                        }

                        break;
                    case "-h":
                    case "--hash-algorithm":
                        if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                        {
                            i++;
                            configuration.HashAlgorithm = args[i];
                        }
                        else
                        {
                            configuration.HashAlgorithm = "";
                        }

                        break;
                    case "-os":
                    case "--overwrite-signatures":
                        configuration.OverwriteSignatures = true;
                        break;
                    case "-ks":
                    case "--keep-signatures":
                        configuration.OverwriteSignatures = false;
                        break;
                    case "-is":
                    case "--ignore-existing-signatures":
                        configuration.IgnoreExistingSignatures = true;
                        break;
                    case "-fs":
                    case "--fail-on-existing-signatures":
                        configuration.IgnoreExistingSignatures = false;
                        break;
                    case "-iu":
                    case "--ignore-unsupported-files":
                        configuration.IgnoreUnsupportedFiles = true;
                        break;
                    case "-fu":
                    case "--fail-on-unsupported-files":
                        configuration.IgnoreUnsupportedFiles = false;
                        break;
                    case "-t":
                    case "--timeout":
                        if (i + 1 < args.Length)
                        {
                            if (int.TryParse(args[i + 1], out var v))
                            {
                                configuration.Timeout = v;
                            }
                            else
                            {
                                log.Error("Config could not be loaded: Invalid timeout value provided");
                                Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                                return null;
                            }

                            i++;
                        }
                        else
                        {
                            log.Error("Config could not be loaded: No timeout value provided");
                            Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                            return null;
                        }

                        break;
                    default:
                        if (File.Exists(arg) || Directory.Exists(arg))
                        {
                            configuration.Sources.Add(arg);
                        }
                        else
                        {
                            log.Error("Config could not be loaded: File or Directory not found '{file}'", arg);
                            Environment.ExitCode = ErrorCodes.FileNotFound;
                            return null;
                        }

                        break;
                }
            }
        }

        return null;
    }

    private static async Task<SigningClientConfiguration> LoadDefaultConfigurationAsync(ILogger log)
    {
        var defaultConfigFilePath = Path.Combine(AppContext.BaseDirectory, "config.json");

        if (File.Exists(defaultConfigFilePath))
        {
            try
            {
                log.Info("Loading config");
                var configuration =
                    JsonSerializer.Deserialize<SigningClientConfiguration>(
                        await File.ReadAllTextAsync(defaultConfigFilePath))!;
                log.Info("Configuration loaded");
                return configuration;
            }
            catch (Exception e)
            {
                log.Error(e, "Config could not be loaded");
                Environment.ExitCode = ErrorCodes.InvalidConfiguration;
                return null;
            }
        }

        return new SigningClientConfiguration();
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
