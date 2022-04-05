using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.ServiceModel;
using System.ServiceModel.Channels;
using NLog;
using SigningServer.Contracts;
using SigningServer.Server.Configuration;

namespace SigningServer.Server
{
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single, ConcurrencyMode = ConcurrencyMode.Multiple)]
    public class SigningServer : ISigningServer
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();
        private HardwareCertificateUnlocker _hardwareCertificateUnlocker;

        public SigningServerConfiguration Configuration { get; private set; }
        public ISigningToolProvider SigningToolProvider { get; }

        public SigningServer(SigningServerConfiguration configuration, ISigningToolProvider signingToolProvider)
        {
            if (configuration == null) throw new ArgumentNullException(nameof(configuration));
            SigningToolProvider = signingToolProvider;
            Initialize(configuration);
        }

        private void Initialize(SigningServerConfiguration configuration)
        {
            Configuration = configuration;

            Log.Info("Validating configuration");
            Configuration = new SigningServerConfiguration
            {
                LegacyPort = configuration.LegacyPort,
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
                    TimeSpan.FromSeconds(Configuration.HardwareCertificateUnlockIntervalInSeconds));

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
                        Log.Info("Loading certificate '{0}'", certificateConfiguration.Thumbprint);
                        certificateConfiguration.LoadCertificate(_hardwareCertificateUnlocker);
                        list.Add(certificateConfiguration);
                    }
                    catch (CryptographicException e)
                    {
                        Log.Error(e,
                            $"Certificate for thumbprint {certificateConfiguration.Thumbprint} in {certificateConfiguration.StoreLocation}/{certificateConfiguration.StoreName} could not be loaded: 0x{e.HResult:X}");
                    }
                    catch (Exception e)
                    {
                        Log.Error(e, $"Certificate loading failed: {e.Message}");
                    }
                }
            }

            if (list.Count == 0)
            {
                throw new InvalidConfigurationException(InvalidConfigurationException.NoValidCertificatesMessage);
            }


            Configuration.Certificates = list.ToArray();

            try
            {
                if (Directory.Exists(Configuration.WorkingDirectory))
                {
                    Log.Info("Working directory exists, cleaning");
                    Directory.Delete(Configuration.WorkingDirectory, true);
                }

                Directory.CreateDirectory(Configuration.WorkingDirectory);
                Log.Info("Working directory created");
            }
            catch (Exception e)
            {
                throw new InvalidConfigurationException(
                    InvalidConfigurationException.CreateWorkingDirectoryFailedMessage, e);
            }

            Log.Info("Working directory: {0}", Configuration.WorkingDirectory);
            Log.Info("Certificates loaded: {0}", list.Count);
        }

        public string[] GetSupportedFileExtensions()
        {
            var remoteIp = RemoteIp;
            Log.Trace($"[{remoteIp}] Requesting supported file extensions");
            return SigningToolProvider.SupportedFileExtensions;
        }

        public string[] GetSupportedHashAlgorithms()
        {
            return SigningToolProvider.SupportedHashAlgorithms;
        }

        public SignFileResponse SignFile(SignFileRequest signFileRequest)
        {
            var signFileResponse = new SignFileResponse();
            signFileResponse.DeleteFailed += (response, file, exception) =>
            {
                Log.Error(exception, $"Failed to delete file '{file}'");
            };
            signFileResponse.DeleteSkipped += (response, file) => { Log.Warn($"Skipped file delete '{file}'"); };
            signFileResponse.DeleteSuccess += (response, file) => { Log.Trace($"Successfully deleted file '{file}'"); };

            var remoteIp = RemoteIp;
            var isLegacy = IsLegacyEndpoint;
            string inputFileName = null;
            try
            {
                //
                // validate input
                if (isLegacy)
                {
                    Log.Warn($"[{remoteIp}] Client is using legacy endpoint!");
                }

                Log.Info(
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
                    certificate = Configuration.Certificates.FirstOrDefault(c => c.IsAnonymous);
                }
                else
                {
                    certificate = Configuration.Certificates.FirstOrDefault(
                        c => c.IsAuthorized(signFileRequest.Username, signFileRequest.Password));
                }

                if (certificate == null)
                {
                    Log.Warn("Unauthorized signing request");
                    signFileResponse.Result = SignFileResponseResult.FileNotSignedUnauthorized;
                    return signFileResponse;
                }

                // 
                // find compatible signing tool
                var signingTool = SigningToolProvider.GetSigningTool(signFileRequest.FileName);
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
                inputFileName = Path.Combine(Configuration.WorkingDirectory, inputFileName);
                using (var targetFile = new FileStream(inputFileName, FileMode.Create, FileAccess.ReadWrite))
                {
                    signFileRequest.FileContent.CopyTo(targetFile);
                }

                //
                // sign file
                var timestampServer = "SHA1".Equals(signFileRequest.HashAlgorithm, StringComparison.OrdinalIgnoreCase)
                    ? Configuration.Sha1TimestampServer
                    : Configuration.TimestampServer;
                signingTool.SignFile(inputFileName, certificate.Certificate, timestampServer,
                    signFileRequest, signFileResponse);

                Log.Info(
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
                        if (!(signFileResponse.FileContent is FileStream))
                        {
                            try
                            {
                                Log.Trace($"Deleting file {inputFileName}");
                                File.Delete(inputFileName);
                                Log.Trace($"File successfully deleted {inputFileName}");
                            }
                            catch (Exception e)
                            {
                                Log.Error(e, "Could not delete input file for failed request");
                            }
                        }
                        else
                        {
                            Log.Trace(
                                $"Delete file skipped for failed request {signFileResponse.Result} {inputFileName}, {signFileResponse.FileContent.GetType()}");
                        }

                        break;
                }
            }
            catch (Exception e)
            {
                Log.Error(e, $"[{remoteIp}] Signing of {signFileRequest.FileName} failed: {e.Message}");
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
                        Log.Error(fileException, $"[{remoteIp}] Failed to delete file {inputFileName}");
                    }
                }
            }

            return signFileResponse;
        }

        private bool IsLegacyEndpoint
        {
            get
            {
                try
                {
                    var context = OperationContext.Current;
                    return context.IncomingMessageProperties.Via.Port == Configuration.LegacyPort;
                }
                catch (Exception e)
                {
                    Log.Error(e, "Could not check for legacy enpdoint");
                    return false;
                }
            }
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
                    Log.Error(e, "Could not load remote IP");
                    return "Unknown";
                }
            }
        }
    }
}