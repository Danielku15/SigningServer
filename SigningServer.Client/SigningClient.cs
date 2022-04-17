using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.Threading;
using NLog;
using SigningServer.Contracts;

namespace SigningServer.Client;

public sealed class SigningClient : IDisposable
{
    private static readonly Logger Log = LogManager.GetCurrentClassLogger();

    private HashSet<string> _supportedFileFormats;
    private readonly SigningClientConfiguration _configuration;
    private ChannelFactory<ISigningServer> _clientFactory;
    private ISigningServer _client;
    private readonly TimeSpan _timeout;
    private HashSet<string> _supportedHashAlgorithms;
    private readonly Uri _signingServer;

    public SigningClient(SigningClientConfiguration configuration)
    {
        _configuration = configuration;
        if (string.IsNullOrWhiteSpace(configuration.SigningServer))
        {
            throw new ArgumentException("Empty SigningServer in configuraiton", nameof(configuration));
        }

        var parts = configuration.SigningServer.Split(new[] { ":" }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2)
        {
            throw new ArgumentException(
                $"Invalid SigningServer specified (expected host:port, found {configuration.SigningServer})",
                nameof(configuration));
        }

        _timeout = TimeSpan.FromSeconds(configuration.Timeout > 0 ? configuration.Timeout : 60);

        var uriBuilder = new UriBuilder
        {
            Scheme = "net.tcp",
            Host = parts[0],
            Port = int.Parse(parts[1])
        };
        _signingServer = uriBuilder.Uri;
        Connect();
    }

    public void Dispose()
    {
        (_clientFactory as IDisposable)?.Dispose();
        // ReSharper disable once SuspiciousTypeConversion.Global
        (_client as IDisposable)?.Dispose();
    }

    public void SignFile(string path)
    {
        // Sometimes via MSBuild there are quotes on the path, here we clean them. 
        path = path.Trim('"');
        Log.Info("Signing '{0}'", path);
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

        Log.Info("Signing file '{0}'", info.FullName);

        if (info.Attributes.HasFlag(FileAttributes.ReadOnly))
        {
            Log.Info("File was readonly, cleaned readonly flag");
            info.Attributes &= ~FileAttributes.ReadOnly;
        }

        var retry = _configuration.Retry;
        do
        {
            try
            {
                var sw = new Stopwatch();
                sw.Start();
                SignFileResponse response;
                using (var request = new SignFileRequest
                       {
                           FileName = info.Name,
                           FileSize = info.Length,
                           OverwriteSignature = _configuration.OverwriteSignatures,
                           Username = _configuration.Username,
                           Password = _configuration.Password,
                           FileContent = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read),
                           HashAlgorithm = _configuration.HashAlgorithm
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
                            using (var fs = new FileStream(file, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
                            {
                                response.FileContent.CopyTo(fs);
                            }
                            sw.Stop();
                            Log.Info("File downloaded, signing finished in {0}ms", sw.ElapsedMilliseconds);
                                
                            retry = 0;
                            break;
                        case SignFileResponseResult.FileResigned:
                            Log.Info("File signed and old signature was removed, start downloading");
                            using (var fs = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                            {
                                response.FileContent.CopyTo(fs);
                            }
                            sw.Stop();
                            Log.Info("File downloaded, signing finished in {0}ms", sw.ElapsedMilliseconds);

                            retry = 0;
                            break;
                        case SignFileResponseResult.FileAlreadySigned:
                            Log.Warn("File is already signed and was therefore skipped");
                            if (!_configuration.IgnoreExistingSignatures)
                            {
                                Log.Info("Signing failed");
                                throw new FileAlreadySignedException();
                            }
                            else
                            {
                                retry = 0;
                            }
                            break;
                        case SignFileResponseResult.FileNotSignedUnsupportedFormat:
                            Log.Warn("File is not supported for signing");
                            if (!_configuration.IgnoreUnsupportedFiles)
                            {
                                Log.Error("Signing failed");
                                throw new UnsupportedFileFormatException();
                            }
                            else
                            {
                                retry = 0;
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
            catch (Exception)
            {
                // wait 1sec if we haf 
                if (retry > 0)
                {
                    Log.Error("Waiting 1sec, then retry signing");
                    Thread.Sleep(1000);
                    try
                    {
                        Dispose();
                    }
                    catch (Exception e)
                    { 
                        Log.Warn(e, "Cleanup of existing connection failed");
                    }
                    Connect();
                }
                else
                {
                    throw;
                }
            }

        } while (retry-- > 0);

    }

    private void Connect()
    {
        Log.Info("Connecting to signing server");
        var binding = new NetTcpBinding
        {
            TransferMode = TransferMode.Streamed,
            MaxReceivedMessageSize = int.MaxValue,
            MaxBufferSize = int.MaxValue,
            OpenTimeout = _timeout,
            SendTimeout = _timeout,
            ReceiveTimeout = _timeout,
            CloseTimeout = _timeout,
            Security = { Mode = SecurityMode.None }
        };

        _clientFactory = new ChannelFactory<ISigningServer>(binding, new EndpointAddress(_signingServer));
        _client = _clientFactory.CreateChannel();

        // ReSharper disable once SuspiciousTypeConversion.Global
        if (_client is IClientChannel channel)
        {
            var sw = new Stopwatch();
            sw.Start();
            channel.Open();
            sw.Stop();
            Log.Info("Connected to signing server in {0}ms", sw.ElapsedMilliseconds);
        }

        _supportedFileFormats = new HashSet<string>(_client.GetSupportedFileExtensions());
        _supportedHashAlgorithms = new HashSet<string>(_client.GetSupportedHashAlgorithms());
        Log.Info("supported file formats: {0}", string.Join(", ", _supportedFileFormats));
        Log.Info("supported hash algorithms: {0}", string.Join(", ", _supportedHashAlgorithms));
    }
}
