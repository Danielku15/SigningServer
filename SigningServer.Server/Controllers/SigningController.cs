using System;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SigningServer.Core;
using SigningServer.Dtos;
using SigningServer.Server.Configuration;
using SigningServer.Server.Util;
using SigningServer.Signing;
using SigningServer.Signing.Configuration;
using SignFileRequestDto = SigningServer.Server.Dtos.SignFileRequestDto;
using SignFileResponseDto = SigningServer.Server.Dtos.SignFileResponseDto;

namespace SigningServer.Server.Controllers;

/// <summary>
/// Exposes Signing Related APIs
/// </summary>
[ApiController]
[Route("signing")]
public class SigningController : Controller
{
    private readonly ILogger<SigningController> _logger;
    private readonly ISigningToolProvider _signingToolProvider;
    private readonly IHashSigningTool _hashSigningTool;
    private readonly SigningServerConfiguration _configuration;
    private readonly ICertificateProvider _certificateProvider;

    public SigningController(
        ILogger<SigningController> logger,
        ISigningToolProvider signingToolProvider,
        IHashSigningTool hashSigningTool,
        SigningServerConfiguration configuration,
        ICertificateProvider certificateProvider)
    {
        _logger = logger;
        _signingToolProvider = signingToolProvider;
        _hashSigningTool = hashSigningTool;
        _configuration = configuration;
        _certificateProvider = certificateProvider;
    }

    /// <summary>
    /// Provides the signing capabilities of the server.
    /// </summary>
    /// <returns>The signing capabilities.</returns>
    [HttpGet("capabilities")]
    public ActionResult<ServerCapabilitiesResponse> GetCapabilities()
    {
        var remoteIp = RemoteIp;
        _logger.LogTrace($"[{remoteIp}] Requesting supported file extensions");
        return Ok(new ServerCapabilitiesResponse(
            _configuration.MaxDegreeOfParallelismPerClient,
            _signingToolProvider.AllTools.Select(tool => new ServerSupportedFormat(
                tool.FormatName,
                tool.SupportedFileExtensions,
                tool.SupportedHashAlgorithms
            )).ToList()
        ));
    }

    /// <summary>
    /// Signs the given input file.
    /// </summary>
    /// <param name="signFileRequest"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [HttpPost("sign")]
    [Produces("multipart/form-data", Type = typeof(SignFileResponseDto))]
    public async Task<SignFileActionResult> SignFileAsync([FromForm, Required] SignFileRequestDto signFileRequest,
        CancellationToken cancellationToken)
    {
        var apiSignFileResponse = new SignFileResponseDto();
        SignFileResponse? coreSignFileResponse = null;
        var remoteIp = RemoteIp;
        string inputFileName;
        Lazy<CertificateConfiguration>? certificate = null;
        try
        {
            var stopwatch = Stopwatch.StartNew();
            //
            // validate input
            _logger.LogInformation(
                $"[{remoteIp}] [Begin] New sign request for file '{signFileRequest.FileToSign?.FileName ?? "missing"}' ({signFileRequest.FileToSign?.Length ?? 0} bytes)");
            if (signFileRequest.FileToSign == null || signFileRequest.FileToSign.Length == 0)
            {
                apiSignFileResponse.Status = SignFileResponseStatus.FileNotSignedError;
                apiSignFileResponse.ErrorMessage = "No file was received";
                return new SignFileActionResult(apiSignFileResponse, null);
            }

            //
            // find certificate
            certificate = _certificateProvider.Get(signFileRequest.Username, signFileRequest.Password);
            if (certificate == null)
            {
                _logger.LogWarning("Unauthorized signing request");
                apiSignFileResponse.Status = SignFileResponseStatus.FileNotSignedUnauthorized;
                return new SignFileActionResult(apiSignFileResponse, null);
            }

            // 
            // find compatible signing tool
            var signingTool = _signingToolProvider.GetSigningTool(signFileRequest.FileToSign.FileName);
            if (signingTool == null)
            {
                apiSignFileResponse.Status = SignFileResponseStatus.FileNotSignedUnsupportedFormat;
                _certificateProvider.Return(signFileRequest.Username, certificate);
                return new SignFileActionResult(apiSignFileResponse, null);
            }

            stopwatch.Stop();
            var preparationTime = stopwatch.ElapsedMilliseconds;
            stopwatch.Restart();

            //
            // upload file to working directory
            inputFileName = signFileRequest.FileToSign.FileName;
            inputFileName = DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" +
                            Path.GetFileNameWithoutExtension(inputFileName) + "_" + Guid.NewGuid() +
                            Path.GetExtension(inputFileName);
            inputFileName = Path.Combine(_configuration.WorkingDirectory, inputFileName);

            if (!Directory.Exists(_configuration.WorkingDirectory))
            {
                try
                {
                    Directory.CreateDirectory(_configuration.WorkingDirectory);
                }
                catch (Exception e)
                {
                    _logger.LogWarning(e, "Could not create working directory");
                }
            }

            await using (var targetFile = new FileStream(inputFileName, FileMode.Create, FileAccess.ReadWrite))
            {
                await signFileRequest.FileToSign.CopyToAsync(targetFile, cancellationToken);
            }

            // register for deletion of input file
            HttpContext.Response.OnCompleted(() =>
            {
                try
                {
                    if (System.IO.File.Exists(inputFileName))
                    {
                        System.IO.File.Delete(inputFileName);
                    }
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Failed to cleanup input file: {inputFileName}", inputFileName);
                }

                return Task.CompletedTask;
            });

            stopwatch.Stop();
            apiSignFileResponse.UploadTimeInMilliseconds = stopwatch.ElapsedMilliseconds;
            stopwatch.Restart();

            //
            // sign file
            var timestampServer = "SHA1".Equals(signFileRequest.HashAlgorithm, StringComparison.OrdinalIgnoreCase)
                ? _configuration.Sha1TimestampServer
                : _configuration.TimestampServer;

            coreSignFileResponse = await signingTool.SignFileAsync(
                new SignFileRequest(
                    inputFileName,
                    new Lazy<X509Certificate2>(() => certificate.Value.Certificate!),
                    new Lazy<AsymmetricAlgorithm>(() => certificate.Value.PrivateKey!),
                    signFileRequest.FileToSign.FileName,
                    timestampServer,
                    signFileRequest.HashAlgorithm,
                    signFileRequest.OverwriteSignature
                ), cancellationToken);


            // only return when signed
            _certificateProvider.Return(signFileRequest.Username, certificate);

            // register for deletion of output file
            if (coreSignFileResponse.ResultFiles is { Count: > 0 })
            {
                HttpContext.Response.OnCompleted(() =>
                {
                    foreach (var resultFile in coreSignFileResponse.ResultFiles)
                    {
                        try
                        {
                            if (System.IO.File.Exists(resultFile.OutputFilePath))
                            {
                                System.IO.File.Delete(resultFile.OutputFilePath);
                            }
                        }
                        catch (Exception e)
                        {
                            _logger.LogError(e, "Failed to cleanup output file {resultFile}",
                                resultFile.OutputFilePath);
                        }
                    }


                    return Task.CompletedTask;
                });
            }

            apiSignFileResponse.ErrorMessage = coreSignFileResponse.ErrorMessage;
            apiSignFileResponse.Status = coreSignFileResponse.Status;

            stopwatch.Stop();
            apiSignFileResponse.SignTimeInMilliseconds = stopwatch.ElapsedMilliseconds + preparationTime;

            _logger.LogInformation(
                $"[{remoteIp}] [Finished] request for file '{signFileRequest.FileToSign.FileName}' finished ({signFileRequest.FileToSign.FileName} bytes, prepared in {preparationTime}ms, uploaded in {apiSignFileResponse.UploadTimeInMilliseconds}ms, signed in {apiSignFileResponse.SignTimeInMilliseconds})");
        }
        catch (Exception e)
        {
            _certificateProvider.Destroy(certificate);

            _logger.LogError(e,
                $"[{remoteIp}] Signing of '{signFileRequest.FileToSign?.Name}' failed: {e.Message} HR[{e.HResult}");
            apiSignFileResponse.Status = SignFileResponseStatus.FileNotSignedError;
            apiSignFileResponse.ErrorMessage = e.Message;
        }

        return new SignFileActionResult(apiSignFileResponse, coreSignFileResponse?.ResultFiles);
    }

    /// <summary>
    /// Signs the given input hash.
    /// </summary>
    /// <param name="signHashRequestDto"></param>
    /// <returns></returns>
    [HttpPost("signhash")]
    [Produces("application/json", Type = typeof(SignHashResponseDto))]
    public SignHashActionResult SignHash([FromBody, Required] SignHashRequestDto signHashRequestDto)
    {
        var remoteIp = RemoteIp;
        var certificate = _certificateProvider.Get(signHashRequestDto.Username, signHashRequestDto.Password);
        try
        {
            //
            // validate input
            _logger.LogInformation(
                $"[{remoteIp}] [Begin] New sign request for hash '{signHashRequestDto.Hash}' ({signHashRequestDto.HashAlgorithm})");
            byte[] hashBytes;
            try
            {
                hashBytes = Convert.FromBase64String(signHashRequestDto.Hash);
            }
            catch
            {
                return new SignHashActionResult(new SignHashResponseDto(
                    SignHashResponseStatus.HashNotSignedError,
                    0,
                    "No base64 encoded bytes were received",
                    string.Empty
                ));
            }

            //
            // find certificate
            if (certificate == null)
            {
                return new SignHashActionResult(new SignHashResponseDto(
                    SignHashResponseStatus.HashNotSignedUnauthorized,
                    0,
                    "Unauthorized signing request",
                    string.Empty
                ));
            }

            var stopwatch = Stopwatch.StartNew();
            stopwatch.Restart();

            //
            // sign hash
            var coreSignFileResponse = _hashSigningTool.SignHash(new SignHashRequest(
                hashBytes,
                certificate.Value.Certificate!,
                certificate.Value.PrivateKey!,
                signHashRequestDto.HashAlgorithm,
                signHashRequestDto.PaddingMode
            ));

            stopwatch.Stop();
            var result = new SignHashActionResult(new SignHashResponseDto(
                coreSignFileResponse.Status,
                stopwatch.ElapsedMilliseconds,
                coreSignFileResponse.ErrorMessage,
                Convert.ToBase64String(coreSignFileResponse.Signature)
            ));

            // only return when signed
            _certificateProvider.Return(signHashRequestDto.Username, certificate);

            _logger.LogInformation(
                $"[{remoteIp}] [Finished] request for hash '{signHashRequestDto.Hash}' finished ({signHashRequestDto.HashAlgorithm}, signed in {stopwatch.ElapsedMilliseconds})");

            return result;
        }
        catch (Exception e)
        {
            _certificateProvider.Destroy(certificate);
            _logger.LogError(e, $"[{remoteIp}] Signing of '{signHashRequestDto.Hash}' failed: {e.Message}");
            return new SignHashActionResult(new SignHashResponseDto(
                SignHashResponseStatus.HashNotSignedError,
                0,
                e.Message,
                string.Empty
            ));
        }
    }

    /// <summary>
    /// Decrypts the given data assuming an RSA encryption
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("decryptrsa")]
    [Produces("application/json", Type = typeof(DecryptRsaResponseDto))]
    public IActionResult DecryptRsa([FromBody, Required] DecryptRsaRequestDto request)
    {
        var remoteIp = RemoteIp;
        var certificate = _certificateProvider.Get(request.Username, request.Password);
        ObjectResult result;
        try
        {
            //
            // validate input
            _logger.LogInformation(
                $"[{remoteIp}] [Begin] New decrypt of RSA data '{request.Data.Length}'");
            byte[] dataBytes;
            try
            {
                dataBytes = Convert.FromBase64String(request.Data);
            }
            catch
            {
                return new ObjectResult(new DecryptRsaResponseDto("No base64 encoded bytes were received", null))
                {
                    StatusCode = StatusCodes.Status400BadRequest
                };
            }

            //
            // find certificate
            if (certificate == null)
            {
                return new ObjectResult(new DecryptRsaResponseDto("Unauthorized signing request", null))
                {
                    StatusCode = StatusCodes.Status401Unauthorized
                };
            }

            var stopwatch = Stopwatch.StartNew();
            stopwatch.Restart();

            if (certificate.Value.PrivateKey is RSA rsa)
            {
                var decrypted = rsa.Decrypt(dataBytes, request.ToPadding());
                result = new ObjectResult(new DecryptRsaResponseDto(null, Convert.ToBase64String(decrypted)));
            }
            else
            {
                return new ObjectResult(new DecryptRsaResponseDto("Certificate is not RSA", null))
                {
                    StatusCode = StatusCodes.Status400BadRequest
                };
            }

            // only return when signed
            _certificateProvider.Return(request.Username, certificate);

            _logger.LogInformation(
                $"[{remoteIp}] [Finished] request for RSA decrypt '{request.Data.Length}' finished, signed in {stopwatch.ElapsedMilliseconds})");

            return result;
        }
        catch (Exception e)
        {
            _certificateProvider.Destroy(certificate);
            _logger.LogError(e, $"[{remoteIp}] Signing of '{request.Data}' failed: {e.Message}");
            return new ObjectResult(new DecryptRsaResponseDto("Signing failed: " + e.Message, null))
            {
                StatusCode = StatusCodes.Status500InternalServerError
            };
        }
    }

    /// <summary>
    /// Downloads a certificate.
    /// </summary>
    /// <param name="loadCertificateRequestDto"></param>
    /// <returns></returns>
    [HttpPost("loadcertificate")]
    [Produces("application/json", Type = typeof(LoadCertificateActionResult))]
    public LoadCertificateActionResult LoadCertificate(
        [FromBody, Required] LoadCertificateRequestDto loadCertificateRequestDto)
    {
        var remoteIp = RemoteIp;
        var certificate =
            _certificateProvider.Get(loadCertificateRequestDto.Username, loadCertificateRequestDto.Password);
        try
        {
            if (certificate == null)
            {
                _logger.LogWarning("Unauthorized certificate load request");
                return new LoadCertificateActionResult(
                    new LoadCertificateResponseDto(LoadCertificateResponseStatus.CertificateNotLoadedUnauthorized, null,
                        null));
            }

            try
            {
                if (loadCertificateRequestDto.IncludeChain)
                {
                    using var ch = new X509Chain();
                    ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    ch.Build(certificate.Value.Certificate!);

                    var collection = new X509Certificate2Collection(ch.ChainElements
                        .Select(e => new X509Certificate2(e.Certificate.RawData)).ToArray());
                    try
                    {
                        var exported =
                            LoadCertificateResponseDto.Export(collection, loadCertificateRequestDto.ExportFormat);
                        return new LoadCertificateActionResult(new LoadCertificateResponseDto(
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
                    using var copyWithoutPrivateKey = new X509Certificate2(certificate.Value.Certificate!.RawData);
                    var exported = LoadCertificateResponseDto.Export(copyWithoutPrivateKey,
                        loadCertificateRequestDto.ExportFormat);
                    return new LoadCertificateActionResult(new LoadCertificateResponseDto(
                        LoadCertificateResponseStatus.CertificateLoaded,
                        null,
                        Convert.ToBase64String(exported)
                    ));
                }
            }
            finally
            {
                // only return when signed
                _certificateProvider.Return(loadCertificateRequestDto.Username, certificate);
            }
        }
        catch (Exception e)
        {
            _certificateProvider.Destroy(certificate);
            _logger.LogError(e, $"[{remoteIp}] Loading of certificate failed: {e.Message}");
            return new LoadCertificateActionResult(new LoadCertificateResponseDto(
                LoadCertificateResponseStatus.CertificateNotLoadedError,
                e.Message,
                null
            ));
        }
    }

    private string RemoteIp => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
