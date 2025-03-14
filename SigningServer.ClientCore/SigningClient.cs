using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SigningServer.Core;
using SigningServer.Dtos;

namespace SigningServer.ClientCore;

public interface ISigningClient : IDisposable
{
    Task InitializeAsync();
    Task SignFilesAsync();
    
    SigningClientConfigurationBase Configuration { get; }
}

public abstract class SigningClient<TConfiguration> : ISigningClient
    where TConfiguration : SigningClientConfigurationBase
{
    protected ServerCapabilitiesResponse? ServerCapabilities { get; set; }
    protected HashSet<string> SupportedFileFormats { get; } = new(StringComparer.OrdinalIgnoreCase);

    public TConfiguration Configuration { get; }
    SigningClientConfigurationBase ISigningClient.Configuration => Configuration;
    
    protected ILogger Logger { get; }

    protected SigningClient(TConfiguration configuration,ILogger logger)
    {
        Configuration = configuration;
        Logger = logger;
    }

    public abstract Task InitializeAsync();

    public async Task SignFilesAsync()
    {
        Logger.LogTrace("Collecting all files");
        var allFiles = Configuration.Sources.SelectMany(source =>
        {
            var fileInfo = new FileInfo(source);
            if (fileInfo.Exists)
            {
                return new[] { fileInfo.FullName };
            }

            return Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories)
                .Where(f => SupportedFileFormats.Contains(Path.GetExtension(f)))
                .ToArray();
        });
        var processingQueue = new ConcurrentQueue<string>(allFiles);

        var numberOfWorkers = Math.Min(Math.Max(1, Configuration.Parallel ?? Environment.ProcessorCount),
            ServerCapabilities!.MaxDegreeOfParallelismPerClient);

        var numberOfFiles = processingQueue.Count;
        Logger.LogInformation("Found {numberOfFiles} files to sign, will sign with {numberOfWorkers} worker", numberOfFiles,
            numberOfWorkers);

        var duplicateFileLookup = new ConcurrentDictionary<string, string>();
        Func<string, string> createDuplicateFileKey;
        
        switch (Configuration.DuplicateFileDetection)
        {
            case DuplicateFileDetectionMode.None:
                createDuplicateFileKey = _ => Guid.NewGuid().ToString(); // no duplicate detection
                break;
            case DuplicateFileDetectionMode.ByFileName:
                createDuplicateFileKey = Path.GetFileName;
                break;
            case DuplicateFileDetectionMode.ByFileHash:
                createDuplicateFileKey = filePath =>
                {
                    using var stream = new BufferedStream(File.OpenRead(filePath), 100000);
                    var sha = SHA256.Create();
                    var checksum = sha.ComputeHash(stream);
                    return Convert.ToHexString(checksum);
                };
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }

        var sw = Stopwatch.StartNew();
        var cancellationSource = new CancellationTokenSource();
        Exception? mainException = null;
        var tasks = Enumerable.Range(0, numberOfWorkers)
            .Select(_ => Task.Run(async () =>
            {
                try
                {
                    await SignFilesAsync(processingQueue,
                        duplicateFileLookup, 
                        createDuplicateFileKey,
                        cancellationSource.Token);
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
        Logger.LogInformation("Finished signing of {numberOfFiles} files in {timeNeeded}ms", numberOfFiles,
            timeNeeded);

        if (mainException != null)
        {
            throw mainException;
        }

        if (!string.IsNullOrWhiteSpace(Configuration.LoadCertificatePath))
        {
            await DoLoadCertificateAsync(cancellationSource.Token);
        }
    }


    protected abstract Task<LoadCertificateResponseDto> LoadCertificateAsync(CancellationToken cancellationToken);

    private async Task DoLoadCertificateAsync(CancellationToken cancellationToken)
    {
        var msg = "certificate" + (Configuration.LoadCertificateChain ? " chain" : "");
        Logger.LogInformation(
            $"Loading certificate {msg} with format {Configuration.LoadCertificateExportFormat} to {Configuration.LoadCertificatePath}");

        var responseDto = await LoadCertificateAsync(cancellationToken);
        switch (responseDto.Status)
        {
            case LoadCertificateResponseStatus.CertificateLoaded:
                Directory.CreateDirectory(Path.GetDirectoryName(Configuration.LoadCertificatePath)!);
                await File.WriteAllBytesAsync(Configuration.LoadCertificatePath!,
                    Convert.FromBase64String(responseDto.CertificateData!),
                    cancellationToken);
                Logger.LogInformation($"Certificate successfully downloaded to {Configuration.LoadCertificatePath}");
                break;
            case LoadCertificateResponseStatus.CertificateNotLoadedError:
                var error = $"Certificate Loading Failed with error '{responseDto.ErrorMessage}'";
                throw new SigningFailedException(error);
            case LoadCertificateResponseStatus.CertificateNotLoadedUnauthorized:
                Logger.LogError("The specified username and password are not recognized on the server ({Status}, {Username})", responseDto.Status, Configuration.CredentialInfo);
                throw new UnauthorizedAccessException();
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private async Task SignFilesAsync(ConcurrentQueue<string> processingQueue, 
        ConcurrentDictionary<string, string> duplicateFileLookup,
        Func<string, string> createDuplicateFileKey,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && processingQueue.TryDequeue(out var nextFile))
        {
            if (!string.IsNullOrEmpty(Configuration.SignHashFileExtension))
            {
                await DoSignHashAsync(nextFile, cancellationToken);
            }
            else
            {
                await DoSignFileAsync(nextFile,
                    duplicateFileLookup,
                    createDuplicateFileKey,
                    cancellationToken);
            }
        }
    }

    protected abstract Task<SignHashResponseDto> SignHashAsync(byte[] hashBytes, CancellationToken cancellationToken);

    private async Task DoSignHashAsync(string file, CancellationToken cancellationToken)
    {
        var info = new FileInfo(file);

        Logger.LogTrace("Signing hash of file '{0}'", info.FullName);

        var retry = Configuration.Retry;
        do
        {
            try
            {
                var sw = new Stopwatch();
                sw.Start();

                var hashBytes = await HashFileAsync(file, cancellationToken);

                var responseDto = await SignHashAsync(hashBytes, cancellationToken);
                switch (responseDto.Status)
                {
                    case SignHashResponseStatus.HashSigned:
                        var extension = Configuration.SignHashFileExtension;
                        if (extension == null || !extension.StartsWith("."))
                        {
                            extension = "." + extension;
                        }

                        var signatureFile = Path.ChangeExtension(info.FullName, extension);
                        await File.WriteAllBytesAsync(signatureFile, Convert.FromBase64String(responseDto.Signature),
                            cancellationToken);
                        Logger.LogInformation($"Hash successfully signed, (sign time: {responseDto.SignTimeInMilliseconds:0}ms)");
                        retry = 0;
                        break;
                    case SignHashResponseStatus.HashNotSignedUnsupportedFormat:
                        throw new UnsupportedFileFormatException(responseDto.ErrorMessage!);
                    case SignHashResponseStatus.HashNotSignedError:
                        var error =
                            $"Signing Failed with error '{responseDto.ErrorMessage}' (sign time: {responseDto.SignTimeInMilliseconds:0}ms)";
                        throw new SigningFailedException(error);
                    case SignHashResponseStatus.HashNotSignedUnauthorized:
                        Logger.LogError("The specified username and password are not recognized on the server ({Status}, {Username})", responseDto.Status, Configuration.CredentialInfo);
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
                    Logger.LogError(e, "Waiting 1sec, then retry signing");
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
        using var hashAlg = CryptoUtils.CreateHashAlgorithmFromName(Configuration.HashAlgorithm ?? "SHA256");
        if (hashAlg == null)
        {
            throw new UnsupportedFileFormatException($"Unsupported hash algorithm {Configuration.HashAlgorithm}");
        }

        await using var stream = File.OpenRead(file);
        return await hashAlg.ComputeHashAsync(stream, cancellationToken);
    }

    protected enum SignFilePartialResultKind
    {
        Status,
        ErrorMessage,
        UploadTime,
        SignTime,
        ResultFile
    }

    protected record SignFileFileResult(string FileName, Stream ContentStream);
    protected record SignFilePartialResult(SignFilePartialResultKind Kind, object Value);

    protected abstract IAsyncEnumerable<SignFilePartialResult> SignFileAsync(string file,
        CancellationToken cancellationToken,
        CancellationToken fileCompletedToken);

    private async Task DoSignFileAsync(string file, 
        ConcurrentDictionary<string, string> duplicateFileLookup,
        Func<string, string> createDuplicateFileKey,
        CancellationToken cancellationToken)
    {
        var info = new FileInfo(file);

        Logger.LogTrace("Signing file '{0}'", info.FullName);

        if (info.Attributes.HasFlag(FileAttributes.ReadOnly))
        {
            Logger.LogTrace("File was readonly, cleaned readonly flag");
            info.Attributes &= ~FileAttributes.ReadOnly;
        }

        var retry = Configuration.Retry;

        do
        {
            using var fileCompletedSource = new CancellationTokenSource();
            try
            {
                var sw = new Stopwatch();
                sw.Start();

                Logger.LogInformation("Start signing file {fileName}", info.FullName);

                var duplicateFileKey = createDuplicateFileKey(info.FullName);
                if (duplicateFileLookup.TryGetValue(duplicateFileKey, out var alreadySignedFilePath))
                {
                    Logger.LogInformation("Found already signed file {existingFileName}, will re-use local file", alreadySignedFilePath);
                    File.Copy(alreadySignedFilePath, info.FullName, true);
                    Logger.LogTrace("File copied from  file {existingFileName} to {targetFileName}", alreadySignedFilePath,
                        info.FullName);
                    return;
                }
                
                
                var results = SignFileAsync(file, cancellationToken, fileCompletedSource.Token);

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
                            Logger.LogTrace(
                                "File successfully signed, will start download (upload time: {uploadTime}ms, sign time: {signTime}ms)",
                                uploadTime.TotalMilliseconds, signTime.TotalMilliseconds);
                            retry = 0;
                            break;
                        case SignFileResponseStatus.FileResigned:
                            Logger.LogTrace(
                                "File signed and old signature was removed, will start download (upload time: {uploadTime}ms, sign time: {signTime}ms)",
                                uploadTime.TotalMilliseconds, signTime.TotalMilliseconds);
                            retry = 0;
                            break;
                        case SignFileResponseStatus.FileAlreadySigned:
                            Logger.LogTrace(
                                "File is already signed and was therefore skipped (upload time: {uploadTime}ms, sign time: {signTime}ms)",
                                uploadTime.TotalMilliseconds, signTime.TotalMilliseconds);
                            if (!Configuration.IgnoreExistingSignatures)
                            {
                                Logger.LogError("Signing failed");
                                throw new FileAlreadySignedException();
                            }

                            retry = 0;
                            break;
                        case SignFileResponseStatus.FileNotSignedUnsupportedFormat:
                            Logger.LogWarning("File is not supported for signing");
                            if (!Configuration.IgnoreUnsupportedFiles)
                            {
                                Logger.LogError("Signing failed");
                                throw new UnsupportedFileFormatException();
                            }

                            retry = 0;

                            break;
                        case SignFileResponseStatus.FileNotSignedError:
                            var error =
                                $"Signing Failed with error '{errorMessage}' (upload time: {uploadTime.TotalMilliseconds:0}ms, sign time: {signTime.TotalMilliseconds:0}ms)";
                            throw new SigningFailedException(error);
                        case SignFileResponseStatus.FileNotSignedUnauthorized:
                            Logger.LogError("The specified username and password are not recognized on the server ({Status}, {Username})", status, Configuration.CredentialInfo);
                            throw new UnauthorizedAccessException();
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                }

                await foreach (var result in results)
                {
                    switch (result.Kind)
                    {
                        case SignFilePartialResultKind.Status:
                            status = (SignFileResponseStatus)result.Value;
                            break;
                        case SignFilePartialResultKind.ErrorMessage:
                            errorMessage = (string)result.Value;
                            break;
                        case SignFilePartialResultKind.UploadTime:
                            uploadTime = (TimeSpan)result.Value;
                            break;
                        case SignFilePartialResultKind.SignTime:
                            signTime = (TimeSpan)result.Value;
                            break;
                        case SignFilePartialResultKind.ResultFile:
                            WriteResponseInfo();

                            var fileInfo = (SignFileFileResult)result.Value;

                            if (status == SignFileResponseStatus.FileSigned)
                            {
                                var downloadWatch = Stopwatch.StartNew();
                                Logger.LogInformation("Downloading file {fileName}", fileInfo.FileName);
                                var targetFileName = Path.Combine(info.DirectoryName!, fileInfo.FileName);
                                await using var targetFile = new FileStream(targetFileName, FileMode.Create,
                                    FileAccess.ReadWrite,
                                    FileShare.None);
                                await using (fileInfo.ContentStream)
                                {
                                    await fileInfo.ContentStream.CopyToAsync(targetFile, cancellationToken);
                                }

                                duplicateFileLookup[duplicateFileKey] = info.FullName;
                                
                                downloadWatch.Stop();
                                Logger.LogTrace("Downloaded file {fileName} in {downloadTime}ms", fileInfo.FileName,
                                    downloadWatch.ElapsedMilliseconds);
                            }
                            else
                            {
                                Logger.LogWarning("Received result file without success, skipping file: {fileName}",
                                    fileInfo.FileName);
                            }

                            break;
                    }
                }

                // ensure response is written
                WriteResponseInfo();
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
                    Logger.LogError(e, "Waiting 1sec, then retry signing");
                    Thread.Sleep(1000);
                }
                else
                {
                    throw;
                }
            }
            finally
            {
                fileCompletedSource.Cancel();
            }
        } while (retry-- > 0);
    }


    protected virtual void Dispose(bool disposing)
    {
        // for implementations
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
