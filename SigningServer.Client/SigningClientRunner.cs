using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SigningServer.ClientCore;

namespace SigningServer.Client;

internal class SigningClientRunner
{
    private readonly ILogger<SigningClientRunner> _logger;
    private readonly ISigningConfigurationLoader _configurationLoader;
    private readonly ISigningClientProvider<SigningClientConfiguration> _clientProvider;

    public SigningClientRunner(
        ILogger<SigningClientRunner> logger,
        ISigningConfigurationLoader configurationLoader,
        ISigningClientProvider<SigningClientConfiguration> clientProvider)
    {
        _logger = logger;
        _configurationLoader = configurationLoader;
        _clientProvider = clientProvider;
    }

    public async Task RunAsync()
    {
        var configuration = await _configurationLoader.LoadConfigurationAsync();
        if (configuration == null)
        {
            if (Environment.ExitCode == 0)
            {
                Environment.ExitCode = ErrorCodes.InvalidConfiguration;
            }
            return;
        }

        foreach (var source in configuration.Sources)
        {
            if (!File.Exists(source) && !Directory.Exists(source))
            {
                _logger.LogError("Config not valid: File or Directory not found '{file}'", source);
                Environment.ExitCode = ErrorCodes.FileNotFound;
                return;
            }
        }

        SigningClient client;
        try
        {
            _logger.LogTrace("Creating client");
            client = (SigningClient)_clientProvider.CreateClient(configuration);
            await client.ConnectAsync();
            _logger.LogTrace("connected to server");
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Could not create signing client");
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
            _logger.LogCritical(e, "Unexpected error happened");
            Environment.ExitCode = ErrorCodes.UnexpectedError;
        }
    }
}
