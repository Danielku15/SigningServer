using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using NLog;
using SigningServer.Core;
using SigningServer.Server.Dtos;

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
            throw new ArgumentException("Empty SigningServer in configuration", nameof(configuration));
        }

        if (!Uri.TryCreate(configuration.SigningServer, UriKind.Absolute, out var signingServerUri))
        {
            throw new ArgumentException("Could not parse SigningServer URL, please specify absolute URL",
                nameof(configuration));
        }

        Configuration = configuration;
        var timeout = TimeSpan.FromSeconds(configuration.Timeout > 0 ? configuration.Timeout : 60);
        _client = new HttpClient { BaseAddress = signingServerUri, Timeout = timeout };
    }

    public async Task ConnectAsync()
    {
        Log.Info("Connecting to signing server");
        _serverCapabilities = await _client.GetFromJsonAsync<ServerCapabilitiesResponse>("signing/capabilities");
        Log.Info("Server Capabilities loaded");

        Log.Trace("Supported Formats:");
        foreach (var supportedFormat in _serverCapabilities!.SupportedFormats)
        {
            Log.Trace($"  {supportedFormat.Name}");
            Log.Trace("    Supported Extensions: {fileExtensions}",
                string.Join(", ", supportedFormat.SupportedFileExtensions));
            Log.Trace("    Supported Hash Algorithms: {hashAlgorithms}",
                string.Join(", ", supportedFormat.SupportedHashAlgorithms));
            foreach (var extension in supportedFormat.SupportedFileExtensions)
            {
                _supportedFileFormats.Add(extension);
            }
        }
    }

    public SigningClient(HttpClient client, params string[] sources)
    {
        Configuration = new SigningClientConfiguration { Sources = sources };
        _client = client;
    }

    public void Dispose()
    {
        _client?.Dispose();
    }

    public async Task SignFilesAsync()
    {
        Log.Trace("Collecting all files");
        var allFiles = Configuration.Sources.SelectMany(source =>
        {
            var fileInfo = new FileInfo(source);
            if (fileInfo.Exists)
            {
                return new[] { fileInfo.FullName };
            }

            return Directory.EnumerateFiles(source!, "*", SearchOption.AllDirectories)
                .Where(f => _supportedFileFormats.Contains(Path.GetExtension(f)))
                .ToArray();
        });
        var processingQueue = new ConcurrentQueue<string>(allFiles);

        var numberOfWorkers = Math.Min(Math.Max(1, Configuration.Parallel ?? Environment.ProcessorCount),
            _serverCapabilities.MaxDegreeOfParallelismPerClient);

        var numberOfFiles = processingQueue.Count;
        Log.Info("Found {numberOfFiles} files to sign, will sign with {numberOfWorkers} worker", numberOfFiles,
            numberOfWorkers);

        var sw = Stopwatch.StartNew();
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

        sw.Stop();
        var timeNeeded = sw.ElapsedMilliseconds;
        Log.Info("Finished signing of {numberOfFiles} files in {timeNeeded}ms", numberOfFiles,
            timeNeeded);

        if (mainException != null)
        {
            throw mainException;
        }

        if (!string.IsNullOrWhiteSpace(Configuration.LoadCertificatePath))
        {
            await LoadCertificateAsync(cancellationSource.Token);
        }
    }

    private async Task LoadCertificateAsync(CancellationToken cancellationToken)
    {
        var msg = "certificate" + (Configuration.LoadCertificateChain ? " chain" : "");
        Log.Info(
            $"Loading certificate {msg} with format {Configuration.LoadCertificateExportFormat} to {Configuration.LoadCertificatePath}");

        var response = await _client.PostAsJsonAsync("signing/loadcertificate",
            new LoadCertificateRequestDto
            {
                Username = Configuration.Username,
                Password = Configuration.Password,
                ExportFormat = Configuration.LoadCertificateExportFormat!.Value,
                IncludeChain = Configuration.LoadCertificateChain
            }, cancellationToken);

        var responseDto =
            await response.Content.ReadFromJsonAsync<LoadCertificateResponseDto>(cancellationToken: cancellationToken);
        if (responseDto == null)
        {
            throw response.StatusCode switch
            {
                HttpStatusCode.OK => new InvalidOperationException("No response body"),
                HttpStatusCode.BadRequest => new UnsupportedFileFormatException(),
                HttpStatusCode.InternalServerError => new InvalidOperationException("Unknown internal error"),
                HttpStatusCode.Unauthorized => new UnauthorizedAccessException(),
                _ => new InvalidOperationException("Unknown error, status code: " + response.StatusCode)
            };
        }

        switch (responseDto.Status)
        {
            case LoadCertificateResponseStatus.CertificateLoaded:
                Directory.CreateDirectory(Path.GetDirectoryName(Configuration.LoadCertificatePath)!);
                await File.WriteAllBytesAsync(Configuration.LoadCertificatePath,
                    Convert.FromBase64String(responseDto.CertificateData),
                    cancellationToken);
                Log.Info($"Certificate successfully downloaded to {Configuration.LoadCertificatePath}");
                break;
            case LoadCertificateResponseStatus.CertificateNotLoadedError:
                var error = $"Certificate Loading Failed with error '{responseDto.ErrorMessage}'";
                throw new SigningFailedException(error);
            case LoadCertificateResponseStatus.CertificateNotLoadedUnauthorized:
                Log.Error("The specified username and password are not recognized on the server");
                throw new UnauthorizedAccessException();
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private async Task SignFilesAsync(ConcurrentQueue<string> processingQueue, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && processingQueue.TryDequeue(out var nextFile))
        {
            if (!string.IsNullOrEmpty(Configuration.SignHashFileExtension))
            {
                await SignHashAsync(nextFile, cancellationToken);
            }
            else
            {
                await SignFileAsync(nextFile, cancellationToken);
            }
        }
    }

    private async Task SignHashAsync(string file, CancellationToken cancellationToken)
    {
        var info = new FileInfo(file);

        Log.Trace("Signing hash of file '{0}'", info.FullName);

        var retry = Configuration.Retry;
        do
        {
            try
            {
                var sw = new Stopwatch();
                sw.Start();

                var hashBytes = await HashFileAsync(file, cancellationToken);

                var response = await _client.PostAsJsonAsync("signing/signhash",
                    new SignHashRequestDto
                    {
                        Username = Configuration.Username,
                        Password = Configuration.Password,
                        HashAlgorithm = Configuration.HashAlgorithm,
                        Hash = Convert.ToBase64String(hashBytes)
                    }, cancellationToken);

                var responseDto =
                    await response.Content.ReadFromJsonAsync<SignHashResponseDto>(cancellationToken: cancellationToken);
                if (responseDto == null)
                {
                    throw response.StatusCode switch
                    {
                        HttpStatusCode.OK => new InvalidOperationException("No response body"),
                        HttpStatusCode.BadRequest => new UnsupportedFileFormatException(),
                        HttpStatusCode.InternalServerError => new InvalidOperationException("Unknown internal error"),
                        HttpStatusCode.Unauthorized => new UnauthorizedAccessException(),
                        _ => new InvalidOperationException("Unknown error, status code: " + response.StatusCode)
                    };
                }

                switch (responseDto.Status)
                {
                    case SignHashResponseStatus.HashSigned:
                        var extension = Configuration.SignHashFileExtension;
                        if (!extension.StartsWith("."))
                        {
                            extension = "." + extension;
                        }

                        var signatureFile = Path.ChangeExtension(info.FullName, extension);
                        await File.WriteAllBytesAsync(signatureFile, Convert.FromBase64String(responseDto.Signature),
                            cancellationToken);
                        Log.Info($"Hash successfully signed, (sign time: {responseDto.SignTimeInMilliseconds:0}ms)");
                        retry = 0;
                        break;
                    case SignHashResponseStatus.HashNotSignedUnsupportedFormat:
                        throw new UnsupportedFileFormatException(responseDto.ErrorMessage);
                    case SignHashResponseStatus.HashNotSignedError:
                        var error =
                            $"Signing Failed with error '{responseDto.ErrorMessage}' (sign time: {responseDto.SignTimeInMilliseconds:0}ms)";
                        throw new SigningFailedException(error);
                    case SignHashResponseStatus.HashNotSignedUnauthorized:
                        Log.Error("The specified username and password are not recognized on the server");
                        throw new UnauthorizedAccessException();
                    default:
                        throw new ArgumentOutOfRangeException();
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
            catch (Exception e)
            {
                // wait 1sec if we haf 
                if (retry > 0)
                {
                    Log.Error(e, "Waiting 1sec, then retry signing");
                    Thread.Sleep(1000);
                }
                else
                {
                    throw;
                }
            }
        } while (retry-- > 0);
    }

    private async Task<byte[]> HashFileAsync(string file, CancellationToken cancellationToken)
    {
        using var hashAlg = HashAlgorithm.Create(Configuration.HashAlgorithm ?? "SHA256");
        if (hashAlg == null)
        {
            throw new UnsupportedFileFormatException($"Unsupported hash algorithm {Configuration.HashAlgorithm}");
        }

        await using var stream = File.OpenRead(file);
        return await hashAlg.ComputeHashAsync(stream, cancellationToken);
    }

    private async Task SignFileAsync(string file, CancellationToken cancellationToken)
    {
        var info = new FileInfo(file);

        Log.Trace("Signing file '{0}'", info.FullName);

        if (info.Attributes.HasFlag(FileAttributes.ReadOnly))
        {
            Log.Trace("File was readonly, cleaned readonly flag");
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

                if (contentType.StartsWith("application/json") ||
                    contentType.StartsWith("application/problem+json"))
                {
                    var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                    throw new IOException(
                        $"Could not load signing response (unexpected JSON response '{contentType}', {responseJson})");
                }

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
                                Log.Trace(
                                    "File successfully signed, will start download (upload time: {uploadTime}ms, sign time: {signTime}ms)",
                                    uploadTime.TotalMilliseconds, signTime.TotalMilliseconds);
                                retry = 0;
                                break;
                            case SignFileResponseStatus.FileResigned:
                                Log.Trace(
                                    "File signed and old signature was removed, will start download (upload time: {uploadTime}ms, sign time: {signTime}ms)",
                                    uploadTime.TotalMilliseconds, signTime.TotalMilliseconds);
                                retry = 0;
                                break;
                            case SignFileResponseStatus.FileAlreadySigned:
                                Log.Trace(
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
                                    Log.Trace("Downloaded file {fileName} in {downloadTime}ms", fileName,
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

                    // ensure response is written
                    WriteResponseInfo();
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
            catch (Exception e)
            {
                // wait 1sec if we haf 
                if (retry > 0)
                {
                    Log.Error(e, "Waiting 1sec, then retry signing");
                    Thread.Sleep(1000);
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
        if (string.IsNullOrEmpty(fileName))
        {
            return fileName;
        }

        return new FileInfo(fileName.Trim('"')).Name; // should be sufficient to avoid unexpected side effects
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
