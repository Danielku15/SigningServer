using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using CoreWCF;
using CoreWCF.Channels;
using Microsoft.Extensions.Logging;
using SigningServer.Contracts;
using SigningServer.Server.Configuration;

namespace SigningServer.Server;

[ServiceBehavior(InstanceContextMode = InstanceContextMode.Single, ConcurrencyMode = ConcurrencyMode.Multiple)]
public class SigningServer : ISigningServer
{
    private HardwareCertificateUnlocker _hardwareCertificateUnlocker;
    private readonly ILogger<SigningServer> _logger;
    private SigningServerConfiguration _configuration;
    private readonly ISigningToolProvider _signingToolProvider;

    public SigningServer(
        ILogger<SigningServer> logger,
        SigningServerConfiguration configuration, ISigningToolProvider signingToolProvider)
    {
        if (configuration == null) throw new ArgumentNullException(nameof(configuration));
        _logger = logger;
        _signingToolProvider = signingToolProvider;
        Initialize(configuration);
    }

    private void Initialize(SigningServerConfiguration configuration)
    {
        _configuration = configuration;

        _logger.LogInformation("Validating configuration");
        _configuration = new SigningServerConfiguration
        {
            Port = configuration.Port,
            TimestampServer = configuration.TimestampServer ?? "",
            Sha1TimestampServer = configuration.TimestampServer ?? "",
            WorkingDirectory = configuration.WorkingDirectory ?? "",
            HardwareCertificateUnlockIntervalInSeconds =
                configuration.HardwareCertificateUnlockIntervalInSeconds > 0
                    ? configuration.HardwareCertificateUnlockIntervalInSeconds
                    : 60 * 60
        };

        _hardwareCertificateUnlocker =
            new HardwareCertificateUnlocker(
                TimeSpan.FromSeconds(_configuration.HardwareCertificateUnlockIntervalInSeconds));

        var list = new List<CertificateConfiguration>();
        if (configuration.Certificates != null)
        {
            foreach (var certificateConfiguration in configuration.Certificates)
            {
                if (certificateConfiguration.Certificate != null)
                {
                    list.Add(certificateConfiguration);
                    continue;
                }

                try
                {
                    _logger.LogInformation("Loading certificate '{0}'", certificateConfiguration.Thumbprint);
                    certificateConfiguration.LoadCertificate(_hardwareCertificateUnlocker);
                    list.Add(certificateConfiguration);
                }
                catch (CryptographicException e)
                {
                    _logger.LogError(e,
                        $"Certificate for thumbprint {certificateConfiguration.Thumbprint} in {certificateConfiguration.StoreLocation}/{certificateConfiguration.StoreName} could not be loaded: 0x{e.HResult:X}");
                }
                catch (Exception e)
                {
                    _logger.LogError(e, $"Certificate loading failed: {e.Message}");
                }
            }
        }

        if (list.Count == 0)
        {
            throw new InvalidConfigurationException(InvalidConfigurationException.NoValidCertificatesMessage);
        }


        _configuration.Certificates = list.ToArray();

        try
        {
            if (Directory.Exists(_configuration.WorkingDirectory))
            {
                _logger.LogInformation("Working directory exists, cleaning");
                Directory.Delete(_configuration.WorkingDirectory, true);
            }

            Directory.CreateDirectory(_configuration.WorkingDirectory);
            _logger.LogInformation("Working directory created");
        }
        catch (Exception e)
        {
            throw new InvalidConfigurationException(
                InvalidConfigurationException.CreateWorkingDirectoryFailedMessage, e);
        }

        _logger.LogInformation("Working directory: {0}", _configuration.WorkingDirectory);
        _logger.LogInformation("Certificates loaded: {0}", list.Count);
    }

    public string[] GetSupportedFileExtensions()
    {
        var remoteIp = RemoteIp;
        _logger.LogTrace($"[{remoteIp}] Requesting supported file extensions");
        return _signingToolProvider.SupportedFileExtensions;
    }

    public string[] GetSupportedHashAlgorithms()
    {
        return _signingToolProvider.SupportedHashAlgorithms;
    }

    [OperationBehavior(AutoDisposeParameters = true)]
    public SignFileResponse SignFile(SignFileRequest signFileRequest)
    {
        var signFileResponse = new SignFileResponse();
        signFileResponse.DeleteFailed += (_, file, exception) =>
        {
            _logger.LogError(exception, $"Failed to delete file '{file}'");
        };
        signFileResponse.DeleteSkipped += (_, file) => { _logger.LogWarning($"Skipped file delete '{file}'"); };
        signFileResponse.DeleteSuccess += (_, file) => { _logger.LogTrace($"Successfully deleted file '{file}'"); };

        var remoteIp = RemoteIp;
        string inputFileName = null;
        try
        {
            //
            // validate input
            _logger.LogInformation(
                $"[{remoteIp}] New sign request for file {signFileRequest.FileName} by {remoteIp} ({signFileRequest.FileSize} bytes)");
            if (signFileRequest.FileSize == 0 || signFileRequest.FileContent == null)
            {
                signFileResponse.Result = SignFileResponseResult.FileNotSignedError;
                signFileResponse.ErrorMessage = "No file was received";
                return signFileResponse;
            }

            //
            // find certificate
            CertificateConfiguration certificate;
            if (string.IsNullOrWhiteSpace(signFileRequest.Username))
            {
                certificate = _configuration.Certificates.FirstOrDefault(c => c.IsAnonymous);
            }
            else
            {
                certificate = _configuration.Certificates.FirstOrDefault(
                    c => c.IsAuthorized(signFileRequest.Username, signFileRequest.Password));
            }

            if (certificate == null)
            {
                _logger.LogWarning("Unauthorized signing request");
                signFileResponse.Result = SignFileResponseResult.FileNotSignedUnauthorized;
                return signFileResponse;
            }

            // 
            // find compatible signing tool
            var signingTool = _signingToolProvider.GetSigningTool(signFileRequest.FileName);
            if (signingTool == null)
            {
                signFileResponse.Result = SignFileResponseResult.FileNotSignedUnsupportedFormat;
                return signFileResponse;
            }

            //
            // upload file to working directory
            inputFileName = signFileRequest.FileName ?? "";
            inputFileName = DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" +
                            Path.GetFileNameWithoutExtension(inputFileName) + "_" + Guid.NewGuid() +
                            (Path.GetExtension(inputFileName));
            inputFileName = Path.Combine(_configuration.WorkingDirectory, inputFileName);
            using (var targetFile = new FileStream(inputFileName, FileMode.Create, FileAccess.ReadWrite))
            {
                signFileRequest.FileContent.CopyTo(targetFile);
            }

            //
            // sign file
            var timestampServer = "SHA1".Equals(signFileRequest.HashAlgorithm, StringComparison.OrdinalIgnoreCase)
                ? _configuration.Sha1TimestampServer
                : _configuration.TimestampServer;
            signingTool.SignFile(inputFileName, 
                certificate.Certificate,
                certificate.PrivateKey,
                timestampServer,
                signFileRequest, signFileResponse);

            _logger.LogInformation(
                $"[{remoteIp}] New sign request for file {signFileRequest.FileName} finished ({signFileRequest.FileSize} bytes)");

            switch (signFileResponse.Result)
            {
                case SignFileResponseResult.FileSigned:
                case SignFileResponseResult.FileResigned:
                    break;
                case SignFileResponseResult.FileAlreadySigned:
                case SignFileResponseResult.FileNotSignedUnsupportedFormat:
                case SignFileResponseResult.FileNotSignedError:
                case SignFileResponseResult.FileNotSignedUnauthorized:
                    // ensure input file is cleaned in error cases where the sign tool does not have a result
                    if (signFileResponse.FileContent is not FileStream)
                    {
                        try
                        {
                            _logger.LogTrace($"Deleting file {inputFileName}");
                            File.Delete(inputFileName);
                            _logger.LogTrace($"File successfully deleted {inputFileName}");
                        }
                        catch (Exception e)
                        {
                            _logger.LogError(e, "Could not delete input file for failed request");
                        }
                    }
                    else
                    {
                        _logger.LogTrace(
                            $"Delete file skipped for failed request {signFileResponse.Result} {inputFileName}, {signFileResponse.FileContent.GetType()}");
                    }

                    break;
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e, $"[{remoteIp}] Signing of {signFileRequest.FileName} failed: {e.Message}");
            signFileResponse.Result = SignFileResponseResult.FileNotSignedError;
            signFileResponse.ErrorMessage = e.Message;
            if (!string.IsNullOrEmpty(inputFileName) && File.Exists(inputFileName))
            {
                try
                {
                    File.Delete(inputFileName);
                }
                catch (Exception fileException)
                {
                    _logger.LogError(fileException, $"[{remoteIp}] Failed to delete file {inputFileName}");
                }
            }
        }

        return signFileResponse;
    }

    private string RemoteIp
    {
        get
        {
            try
            {
                var context = OperationContext.Current;
                var properties = context.IncomingMessageProperties;
                if (properties[RemoteEndpointMessageProperty.Name] is RemoteEndpointMessageProperty endpoint)
                {
                    return $"{endpoint.Address}:{endpoint.Port}";
                }

                return "Unknown";
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Could not load remote IP");
                return "Unknown";
            }
        }
    }
}