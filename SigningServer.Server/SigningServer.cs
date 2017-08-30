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
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single)]
    public class SigningServer : ISigningServer
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();

        public SigningServerConfiguration Configuration { get; private set; }
        public ISigningToolProvider SigningToolProvider { get; set; }

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
            Configuration = new SigningServerConfiguration();
            Configuration.TimestampServer = configuration.TimestampServer ?? "";
            Configuration.WorkingDirectory = configuration.WorkingDirectory ?? "";

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
                        certificateConfiguration.LoadCertificate();
                        list.Add(certificateConfiguration);
                    }
                    catch (CryptographicException e)
                    {
                        Log.Error(e, $"Certificate for thumbprint {certificateConfiguration.Thumbprint} in {certificateConfiguration.StoreLocation}/{certificateConfiguration.StoreName} coult not be loaded: 0x{e.HResult.ToString("X")}");
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
                throw new InvalidConfigurationException(InvalidConfigurationException.CreateWorkingDirectoryFailedMessage, e);
            }

            Log.Info("Working directory: {0}", Configuration.WorkingDirectory);
            Log.Info("Certificates loaded: {0}", list.Count);
        }

        public string[] GetSupportedFileExtensions()
        {
            return SigningToolProvider.SupportedFileExtensions;
        }

        public string[] GetSupportedHashAlgorithms()
        {
            return SigningToolProvider.SupportedHashAlgorithms;
        }

        public SignFileResponse SignFile(SignFileRequest signFileRequest)
        {
            var signFileResponse = new SignFileResponse();
            var remoteIp = RemoteIp;
            string inputFileName = null;
            try
            {
                //
                // validate input
                Log.Info("New sign request for file {0} by {1} ({2} bytes)", signFileRequest.FileName, remoteIp, signFileRequest.FileSize);
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
                inputFileName = DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" + Path.GetFileNameWithoutExtension(inputFileName) + "_" + Guid.NewGuid() + (Path.GetExtension(inputFileName));
                inputFileName = Path.Combine(Configuration.WorkingDirectory, inputFileName);
                using (var targetFile = new FileStream(inputFileName, FileMode.Create, FileAccess.ReadWrite))
                {
                    signFileRequest.FileContent.CopyTo(targetFile);
                }

                //
                // sign file
                signingTool.SignFile(inputFileName, certificate.Certificate, Configuration.TimestampServer, signFileRequest, signFileResponse);

                Log.Info("New sign request for file {0} finished ({1} bytes)", signFileRequest.FileName, signFileRequest.FileSize);
            }
            catch (Exception e)
            {
                Log.Error(e, $"Signing of {signFileRequest.FileName} by {remoteIp} failed: {e.Message}");
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
                        Log.Error(fileException, $"Failed to delete file {inputFileName} by {remoteIp}");
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
                    var endpoint = properties[RemoteEndpointMessageProperty.Name] as RemoteEndpointMessageProperty;
                    return endpoint?.Address ?? "Unknown";
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
