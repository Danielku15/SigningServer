using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using NLog;
using SigningServer.Core;

namespace SigningServer.Client;

public sealed class SigningClient : IDisposable
{
    private static readonly Logger Log = LogManager.GetCurrentClassLogger();

    private readonly HttpClient _client;
    private ServerCapabilitiesResponse _serverCapabilities;
    private readonly HashSet<string> _supportedFileFormats = new(StringComparer.OrdinalIgnoreCase);

    public SigningClientConfiguration Configuration { get; }

    public SigningClient(SigningClientConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(configuration.SigningServer))
        {
            throw new ArgumentException("Empty SigningServer in configuraiton", nameof(configuration));
        }

        if (!Uri.TryCreate(configuration.SigningServer, UriKind.Absolute, out var signingServerUri))
        {
            throw new ArgumentException("Could not parse SigningServer URL, please specify absolute URL",
                nameof(configuration));
        }

        var timeout = TimeSpan.FromSeconds(configuration.Timeout > 0 ? configuration.Timeout : 60);
        _client = new HttpClient { BaseAddress = signingServerUri, Timeout = timeout };
    }

    public async Task ConnectAsync()
    {
        Log.Info("Connecting to signing server");

        _serverCapabilities = await _client.GetFromJsonAsync<ServerCapabilitiesResponse>("signing/capabilities");
        Log.Info("Server Capabilities loaded");

        Log.Info("Supported Formats:");
        foreach (var supportedFormat in _serverCapabilities!.SupportedFormats)
        {
            Log.Info($"  {supportedFormat.Name}");
            Log.Info("    Supported Extensions: {fileExtensions}",
                string.Join(", ", supportedFormat.SupportedFileExtensions));
            Log.Info("    Supported Hash Algorithms: {hashAlgorithms}",
                string.Join(", ", supportedFormat.SupportedHashAlgorithms));
            foreach (var extension in supportedFormat.SupportedFileExtensions)
            {
                _supportedFileFormats.Add(extension);
            }
        }
    }

    public SigningClient(HttpClient client, params string[] sources)
    {
        Configuration = new SigningClientConfiguration
        {
            Sources = sources
        };
        _client = client;
    }

    public void Dispose()
    {
        _client?.Dispose();
    }

    public async Task SignFilesAsync()
    {
        Log.Info("Collecting all files");
        var allFiles = Configuration.Sources.SelectMany(source =>
        {
            if (File.Exists(source))
            {
                return new[] { source };
            }

            return Directory.EnumerateFiles(source!, "*", SearchOption.AllDirectories)
                .Where(f => _supportedFileFormats.Contains(Path.GetExtension(f)))
                .ToArray();
        });
        var processingQueue = new ConcurrentQueue<string>(allFiles);

        var numberOfWorkers = Math.Min(Math.Max(1, Configuration.Parallel ?? Environment.ProcessorCount),
            _serverCapabilities.MaxDegreeOfParallelismPerClient);

        Log.Info("Found {numberOfFiles} files to sign, will sign with {numberOfWorkers}", processingQueue.Count,
            numberOfWorkers);

        var cancellationSource = new CancellationTokenSource();
        Exception mainException = null;
        var tasks = Enumerable.Range(0, numberOfWorkers)
            .Select(_ => Task.Run(async () =>
            {
                try
                {
                    await SignFilesAsync(processingQueue, cancellationSource.Token);
                }
                catch (OperationCanceledException) when (cancellationSource.IsCancellationRequested)
                {
                    // Ignore "official" cancellations
                }
                catch (Exception e) when (!cancellationSource.IsCancellationRequested)
                {
                    mainException = e;
                    cancellationSource.Cancel();
                }
                catch
                {
                    // Ignore other exceptions when we already cancelled.
                }
            }, cancellationSource.Token));

        await Task.WhenAll(tasks);

        if (mainException != null)
        {
            throw mainException;
        }
    }

    private async Task SignFilesAsync(ConcurrentQueue<string> processingQueue, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && processingQueue.TryDequeue(out var nextFile))
        {
            await SignFileAsync(nextFile, cancellationToken);
        }
    }

    private async Task SignFileAsync(string file, CancellationToken cancellationToken)
    {
        var info = new FileInfo(file);

        Log.Info("Signing file '{0}'", info.FullName);

        if (info.Attributes.HasFlag(FileAttributes.ReadOnly))
        {
            Log.Info("File was readonly, cleaned readonly flag");
            info.Attributes &= ~FileAttributes.ReadOnly;
        }

        var retry = Configuration.Retry;
        do
        {
            try
            {
                var sw = new Stopwatch();
                sw.Start();

                var content = new MultipartFormDataContent(Guid.NewGuid().ToString("N"));
                if (!string.IsNullOrEmpty(Configuration.Username))
                {
                    content.Add(new StringContent(Configuration.Username), "Username");
                }

                if (!string.IsNullOrEmpty(Configuration.Password))
                {
                    content.Add(new StringContent(Configuration.Password), "Password");
                }

                content.Add(new StringContent(Configuration.OverwriteSignatures.ToString().ToLowerInvariant()),
                    "OverwriteSignature");
                if (!string.IsNullOrEmpty(Configuration.HashAlgorithm))
                {
                    content.Add(new StringContent(Configuration.HashAlgorithm.ToLowerInvariant()),
                        "HashAlgorithm");
                }


                HttpResponseMessage response;
                await using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    content.Add(new StreamContent(fs, 1024 * 1024), "FileToSign", Path.GetFileName(file));
                    response = await _client.PostAsync("signing/sign", content, cancellationToken);
                }

                var contentType = response.Content.Headers.TryGetValues("Content-Type", out var contentTypes)
                    ? contentTypes.FirstOrDefault() ?? string.Empty
                    : string.Empty;
                if (!contentType.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException($"Could not load signing response (unexpected content type '{contentType}')");
                }

                if (!TryParseBoundary(contentType, out var boundary))
                {
                    throw new IOException(
                        $"Could not load signing response (boundary missing in content type '{contentType}')");
                }


                await using (var stream = await response.Content.ReadAsStreamAsync(cancellationToken))
                {
                    var reader = new MultipartReader(boundary, stream);

                    var status = SignFileResponseStatus.FileSigned;
                    var errorMessage = string.Empty;
                    var uploadTime = TimeSpan.Zero;
                    var signTime = TimeSpan.Zero;
                    var responseInfoWritten = false;

                    void WriteResponseInfo()
                    {
                        if (responseInfoWritten)
                        {
                            return;
                        }

                        responseInfoWritten = true;
                        switch (status)
                        {
                            case SignFileResponseStatus.FileSigned:
                                Log.Info(
                                    "File successfully signed, will start download (upload time: {uploadTime}ms, sign time: {signTime}ms)",
                                    uploadTime.TotalMilliseconds, signTime.TotalMilliseconds);
                                retry = 0;
                                break;
                            case SignFileResponseStatus.FileResigned:
                                Log.Info(
                                    "File signed and old signature was removed, will start download (upload time: {uploadTime}ms, sign time: {signTime}ms)",
                                    uploadTime.TotalMilliseconds, signTime.TotalMilliseconds);
                                retry = 0;
                                break;
                            case SignFileResponseStatus.FileAlreadySigned:
                                Log.Info(
                                    "File is already signed and was therefore skipped (upload time: {uploadTime}ms, sign time: {signTime}ms)",
                                    uploadTime.TotalMilliseconds, signTime.TotalMilliseconds);
                                if (!Configuration.IgnoreExistingSignatures)
                                {
                                    Log.Error("Signing failed");
                                    throw new FileAlreadySignedException();
                                }

                                retry = 0;
                                break;
                            case SignFileResponseStatus.FileNotSignedUnsupportedFormat:
                                Log.Warn("File is not supported for signing");
                                if (!Configuration.IgnoreUnsupportedFiles)
                                {
                                    Log.Error("Signing failed");
                                    throw new UnsupportedFileFormatException();
                                }

                                retry = 0;

                                break;
                            case SignFileResponseStatus.FileNotSignedError:
                                var error =
                                    $"Signing Failed with error '{errorMessage}' (upload time: {uploadTime.TotalMilliseconds:0}ms, sign time: {signTime.TotalMilliseconds:0}ms)";
                                throw new SigningFailedException(error);
                            case SignFileResponseStatus.FileNotSignedUnauthorized:
                                Log.Error("The specified username and password are not recognized on the server");
                                throw new UnauthorizedAccessException();
                            default:
                                throw new ArgumentOutOfRangeException();
                        }
                    }

                    while (await reader.ReadNextSectionAsync(cancellationToken) is { } section)
                    {
                        if (!section.Headers.TryGetValue("Content-Disposition", out var contentDispositionValue))
                        {
                            throw new IOException(
                                $"Could not load signing response (missing Content-Disposition on response section)");
                        }

                        if (!ContentDispositionHeaderValue.TryParse(contentDispositionValue,
                                out var contentDisposition))
                        {
                            throw new IOException(
                                $"Could not load signing response (malformed Content-Disposition on response section)");
                        }

                        if (string.IsNullOrEmpty(contentDisposition.Name))
                        {
                            throw new IOException(
                                $"Could not load signing response (missing name on response section)");
                        }

                        var fileName = contentDisposition.FileName ?? string.Empty;
                        fileName = Sanitize(fileName);

                        switch (contentDisposition.Name.ToLowerInvariant())
                        {
                            case "status":
                                var statusValue = await ReadAsStringAsync(section.Body);
                                if (!Enum.TryParse(statusValue, true, out status))
                                {
                                    status = SignFileResponseStatus.FileSigned;
                                    Log.Warn("Unknown status value: {status}. Ignoring and trying to proceed",
                                        statusValue);
                                }

                                break;
                            case "errormessage":
                                errorMessage = await ReadAsStringAsync(section.Body);
                                break;
                            case "uploadtimeinmilliseconds":
                                var uploadTimeValue = await ReadAsStringAsync(section.Body);
                                if (long.TryParse(uploadTimeValue, out var uploadTimeInMilliseconds))
                                {
                                    uploadTime = TimeSpan.FromMilliseconds(uploadTimeInMilliseconds);
                                }
                                else
                                {
                                    Log.Warn("Could not parse upload time: {time}", uploadTimeValue);
                                }

                                break;
                            case "signtimeinmilliseconds":
                                var signTimeValue = await ReadAsStringAsync(section.Body);
                                if (long.TryParse(signTimeValue, out var signTimeInMilliseconds))
                                {
                                    signTime = TimeSpan.FromMilliseconds(signTimeInMilliseconds);
                                }
                                else
                                {
                                    Log.Warn("Could not parse sign time: {time}", signTimeValue);
                                }

                                break;

                            case "resultfiles":
                                WriteResponseInfo();

                                if (status == SignFileResponseStatus.FileSigned)
                                {
                                    var downloadWatch = Stopwatch.StartNew();
                                    Log.Info("Downloading file {fileName}", fileName);
                                    var targetFileName = Path.Combine(info.DirectoryName!, fileName);
                                    await using var targetFile = new FileStream(targetFileName, FileMode.Create,
                                        FileAccess.ReadWrite,
                                        FileShare.None);
                                    await section.Body.CopyToAsync(targetFile, cancellationToken);
                                    downloadWatch.Stop();
                                    Log.Info("Downloaded file {fileName} in {downloadTime}ms", fileName,
                                        downloadWatch.ElapsedMilliseconds);
                                }
                                else
                                {
                                    Log.Warn("Received result file without success, skipping file: {fileName}",
                                        fileName);
                                }

                                break;
                            default:
                                Log.Warn("Unknown response value: {name}, ignoring data", contentDisposition.Name);
                                break;
                        }
                    }
                }
            }
            catch (FileAlreadySignedException)
            {
                // no need for retry with already signed error
                throw;
            }
            catch (UnsupportedFileFormatException)
            {
                // no need for retry with unsupported file
                throw;
            }
            catch (UnauthorizedAccessException)
            {
                // no need for retry with wrong credentials
                throw;
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
                }
                else
                {
                    throw;
                }
            }
        } while (retry-- > 0);
    }

    private string Sanitize(string fileName)
    {
        return Path.GetFileName(fileName); // should be sufficient to avoid unexpected side effects
    }

    private async Task<string> ReadAsStringAsync(Stream sectionBody)
    {
        using var ms = new MemoryStream();
        await sectionBody.CopyToAsync(ms);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static readonly Regex BoundaryRegex =
        new("boundary=([^,]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static bool TryParseBoundary(string contentType, out string boundary)
    {
        boundary = null;
        var match = BoundaryRegex.Match(contentType);
        if (!match.Success)
        {
            return false;
        }

        boundary = match.Groups[1].Value;
        return true;
    }
}
