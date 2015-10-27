using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.ServiceModel;
using NLog;
using SigningServer.Contracts;

namespace SigningServer.Client
{
    public sealed class SigningClient : IDisposable
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();

        private HashSet<string> _supportedFileFormats;
        private readonly SigningClientConfiguration _configuration;
        private ChannelFactory<ISigningServer> _clientFactory;
        private ISigningServer _client;

        public SigningClient(SigningClientConfiguration configuration)
        {
            _configuration = configuration;
            Uri signingServer;
            if (string.IsNullOrWhiteSpace(configuration.SigningServer))
            {
                throw new ArgumentException("Empty SigningServer in configuraiton", nameof(configuration));
            }

            var parts = configuration.SigningServer.Split(new[] { ":" }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
            {
                throw new ArgumentException(
                    $"Invalid SigningServer specified (expected host:port, found {configuration.SigningServer})",
                    "configuration");
            }

            var uriBuilder = new UriBuilder
            {
                Scheme = "net.tcp",
                Host = parts[0],
                Port = int.Parse(parts[1])
            };
            signingServer = uriBuilder.Uri;

            Connect(signingServer);
        }

        public void Dispose()
        {
            (_clientFactory as IDisposable)?.Dispose();
            (_client as IDisposable)?.Dispose();
        }

        public void SignFile(string path)
        {
            var full = Path.GetFullPath(path);
            if (Directory.Exists(full))
            {
                var files = Directory.EnumerateFiles(full, "*", SearchOption.AllDirectories)
                    .Where(f => _supportedFileFormats.Contains(Path.GetExtension(f))).ToArray();
                Log.Info("Processing directory '{0}'", full);
                Log.Info("  Found {0} files", files.Length);
                foreach (var file in files)
                {
                    InternalSignFile(file);
                }
            }
            else if (File.Exists(full))
            {
                Log.Info("Processing file '{0}'", full);
                InternalSignFile(full);
            }
            else
            {
                Log.Error("File or directory '{0}' not found", full);
                throw new FileNotFoundException(path);
            }
        }

        private void InternalSignFile(string file)
        {
            var info = new FileInfo(file);
            SignFileResponse response;

            Log.Info("Signing file '{0}'", info.FullName);
            using (var request = new SignFileRequest
            {
                FileName = info.Name,
                FileSize = info.Length,
                OverwriteSignature = _configuration.OverwriteSignatures,
                Username = _configuration.Username,
                Password = _configuration.Password,
                FileContent = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read)
            })
            {
                response = _client.SignFile(request);
            }

            using (response)
            {
                switch (response.Result)
                {
                    case SignFileResponseResult.FileSigned:
                        Log.Info("File signed, start downloading");
                        using (var fs = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                        {
                            response.FileContent.CopyTo(fs);
                        }
                        Log.Info("File downloaded");
                        break;
                    case SignFileResponseResult.FileResigned:
                        Log.Info("File signed and old signature was removed, start downloading");
                        using (var fs = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                        {
                            response.FileContent.CopyTo(fs);
                        }
                        Log.Info("File downloaded");
                        break;
                    case SignFileResponseResult.FileAlreadySigned:
                        Log.Warn("File is already signed and was therefore skipped");
                        if (!_configuration.IgnoreExistingSignatures)
                        {
                            Log.Info("Signing failed");
                            throw new FileAlreadySignedException();
                        }
                        break;
                    case SignFileResponseResult.FileNotSignedUnsupportedFormat:
                        Log.Warn("File is not supported for signing");
                        if (!_configuration.IgnoreUnsupportedFiles)
                        {
                            Log.Error("Signing failed");
                            throw new UnsupportedFileFormatException();
                        }
                        break;
                    case SignFileResponseResult.FileNotSignedError:
                        throw new SigningFailedException(response.ErrorMessage);
                    case SignFileResponseResult.FileNotSignedUnauthorized:
                        Log.Error("The specified username and password are not recognized on the server");
                        throw new UnauthorizedAccessException();
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }
        }

        private void Connect(Uri signingServer)
        {
            Log.Info("Connecting to signing server");
            _clientFactory = new ChannelFactory<ISigningServer>(new NetTcpBinding
            {
                TransferMode = TransferMode.Streamed
            }, signingServer.ToString());
            _client = _clientFactory.CreateChannel();

            _supportedFileFormats = new HashSet<string>(_client.GetSupportedFileExtensions());
            Log.Info("Connected, supported file formats: {0}", string.Join(", ", _supportedFileFormats));
        }
    }
}
