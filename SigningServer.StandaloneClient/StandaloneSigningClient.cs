using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SigningServer.ClientCore;
using SigningServer.Core;
using SigningServer.Dtos;
using SigningServer.Signing;

namespace SigningServer.StandaloneClient;

public class StandaloneSigningClient : SigningClient<StandaloneSigningClientConfiguration>
{
    private readonly IHashSigningTool _hashSigningTool;
    private readonly ISigningToolProvider _signingToolProvider;

    public StandaloneSigningClient(StandaloneSigningClientConfiguration configuration,
        ILogger<StandaloneSigningClient> logger,
        IHashSigningTool hashSigningTool, ISigningToolProvider signingToolProvider) : base(configuration,
        logger)
    {
        if (string.IsNullOrEmpty(configuration.WorkingDirectory))
        {
            configuration.WorkingDirectory = Path.GetTempPath();
        }
        _hashSigningTool = hashSigningTool;
        _signingToolProvider = signingToolProvider;
    }


    protected override Task<SignHashResponseDto> SignHashAsync(byte[] hashBytes,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        var certificate = Configuration.Server;
        var coreSignFileResponse = _hashSigningTool.SignHash(new SignHashRequest(
            hashBytes,
            certificate.Certificate!,
            certificate.PrivateKey!,
            Configuration.HashAlgorithm!,
            Configuration.RsaSignaturePaddingMode
        ));

        stopwatch.Stop();

        return Task.FromResult(new SignHashResponseDto(coreSignFileResponse.Status,
            stopwatch.ElapsedMilliseconds,
            coreSignFileResponse.ErrorMessage,
            Convert.ToBase64String(coreSignFileResponse.Signature)
        ));
    }


    protected override Task<LoadCertificateResponseDto> LoadCertificateAsync(CancellationToken cancellationToken)
    {
        if (Configuration.LoadCertificateChain)
        {
            using var ch = new X509Chain();
            ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            ch.Build(Configuration.Server.Certificate!);

            var collection = new X509Certificate2Collection(ch.ChainElements
                .Select(e => new X509Certificate2(e.Certificate.RawData)).ToArray());
            try
            {
                var exported =
                    LoadCertificateResponseDto.Export(collection, Configuration.LoadCertificateExportFormat!.Value);
                return Task.FromResult(new LoadCertificateResponseDto(
                    LoadCertificateResponseStatus.CertificateLoaded,
                    null,
                    Convert.ToBase64String(exported)
                ));
            }
            finally
            {
                foreach (var cert in collection)
                {
                    cert.Dispose();
                }
            }
        }
        else
        {
            using var copyWithoutPrivateKey = new X509Certificate2(Configuration.Server.Certificate!.RawData);
            var exported = LoadCertificateResponseDto.Export(copyWithoutPrivateKey,
                Configuration.LoadCertificateExportFormat!.Value);
            return Task.FromResult(new LoadCertificateResponseDto(
                LoadCertificateResponseStatus.CertificateLoaded,
                null,
                Convert.ToBase64String(exported)
            ));
        }
    }

    protected override async IAsyncEnumerable<SignFilePartialResult> SignFileAsync(string file,
        [EnumeratorCancellation] CancellationToken cancellationToken,
        CancellationToken fileCompletedToken)
    {
        var signFileName = Path.GetFileName(file);
        var signingTool = _signingToolProvider.GetSigningTool(signFileName);
        if (signingTool == null)
        {
            yield return new SignFilePartialResult(SignFilePartialResultKind.Status,
                SignFileResponseStatus.FileNotSignedUnsupportedFormat);
            yield break;
        }

        var stopwatch = Stopwatch.StartNew();

        //
        // upload file to working directory
        var inputFileName = DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" +
                            Path.GetFileNameWithoutExtension(signFileName) + "_" + Guid.NewGuid() +
                            Path.GetExtension(signFileName);
        inputFileName = Path.Combine(Configuration.WorkingDirectory, inputFileName);

        if (!Directory.Exists(Configuration.WorkingDirectory))
        {
            try
            {
                Directory.CreateDirectory(Configuration.WorkingDirectory);
            }
            catch (Exception e)
            {
                Logger.LogWarning(e, "Could not create working directory");
            }
        }

        File.Copy(file, inputFileName, true);
        stopwatch.Stop();
        var uploadTimeInMilliseconds = stopwatch.ElapsedMilliseconds;
        stopwatch.Restart();

        void SafeDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (Exception e)
            {
                Logger.LogError(e, "Failed to cleanup file: {path}", path);
            }
        }

        fileCompletedToken.Register(() =>
        {
            SafeDelete(inputFileName);
        });

        //
        // sign file
        var coreSignFileResponse = await signingTool.SignFileAsync(
            new SignFileRequest(
                inputFileName,
                new Lazy<ValueTask<X509Certificate2>>(() => ValueTask.FromResult(Configuration.Server.Certificate!)),
                new Lazy<ValueTask<AsymmetricAlgorithm>>(() => ValueTask.FromResult(Configuration.Server.PrivateKey!)),
                signFileName,
                Configuration.TimestampServer,
                Configuration.HashAlgorithm,
                Configuration.OverwriteSignatures
            ), cancellationToken);

        if (coreSignFileResponse.ResultFiles != null)
        {
            foreach (var outputFile in coreSignFileResponse.ResultFiles)
            {
                fileCompletedToken.Register(() =>
                {
                    SafeDelete(outputFile.OutputFilePath);
                });
            }
        }


        stopwatch.Stop();

        var signTimeInMilliseconds = stopwatch.ElapsedMilliseconds;

        yield return new SignFilePartialResult(SignFilePartialResultKind.Status, coreSignFileResponse.Status);
        yield return new SignFilePartialResult(SignFilePartialResultKind.ErrorMessage,
            coreSignFileResponse.ErrorMessage);
        yield return new SignFilePartialResult(SignFilePartialResultKind.SignTime, TimeSpan.FromMilliseconds(signTimeInMilliseconds));
        yield return new SignFilePartialResult(SignFilePartialResultKind.UploadTime, TimeSpan.FromMilliseconds(uploadTimeInMilliseconds));
        if (coreSignFileResponse.ResultFiles != null)
        {
            foreach (var outputFile in coreSignFileResponse.ResultFiles)
            {
                yield return new SignFilePartialResult(SignFilePartialResultKind.ResultFile,
                    new SignFileFileResult(
                        outputFile.FileName,
                        File.OpenRead(outputFile.OutputFilePath)
                    ));
            }
        }
    }

    public override async Task InitializeAsync()
    {
        ServerCapabilities = new ServerCapabilitiesResponse(
            Configuration.Parallel ?? 4,
            _signingToolProvider.AllTools.Select(tool => new ServerSupportedFormat(
                tool.FormatName,
                tool.SupportedFileExtensions,
                tool.SupportedHashAlgorithms
            )).ToList()
        );

        await Configuration.Server.LoadCertificateAsync(Logger, null /* no HSM Support */);
    }
}
