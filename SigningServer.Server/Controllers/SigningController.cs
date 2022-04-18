using System;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SigningServer.Core;
using SigningServer.Server.Configuration;
using SigningServer.Server.SigningTool;

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
    private readonly SigningServerConfiguration _configuration;

    public SigningController(
        ILogger<SigningController> logger,
        ISigningToolProvider signingToolProvider,
        SigningServerConfiguration configuration)
    {
        _logger = logger;
        _signingToolProvider = signingToolProvider;
        _configuration = configuration;
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
        return Ok(new ServerCapabilitiesResponse
        {
            SupportedFormats = _signingToolProvider.AllTools.Select(tool => new ServerSupportedFormat
            {
                Name = tool.Name,
                SupportedFileExtensions = tool.SupportedFileExtensions,
                SupportedHashAlgorithms = tool.SupportedHashAlgorithms,
            }).ToList()
        });
    }

    /// <summary>
    /// Signs the given input file.
    /// </summary>
    /// <param name="signFileRequest"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [HttpPost("sign")]
    [Produces("multipart/form-data", Type = typeof(Models.SignFileResponse))]
    public async Task<SignFileActionResult> SignFileAsync([FromForm, Required] Models.SignFileRequest signFileRequest,
        CancellationToken cancellationToken)
    {
        var apiSignFileResponse = new Models.SignFileResponse();
        SignFileResponse coreSignFileResponse = null;
        var remoteIp = RemoteIp;
        string inputFileName;
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
                apiSignFileResponse.Status = SignFileResponseStatus.FileNotSignedUnauthorized;
                return new SignFileActionResult(apiSignFileResponse, null);
            }

            // 
            // find compatible signing tool
            var signingTool = _signingToolProvider.GetSigningTool(signFileRequest.FileToSign.FileName);
            if (signingTool == null)
            {
                apiSignFileResponse.Status = SignFileResponseStatus.FileNotSignedUnsupportedFormat;
                return new SignFileActionResult(apiSignFileResponse, null);
            }

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

            coreSignFileResponse = signingTool.SignFile(new SignFileRequest
            {
                InputFilePath = inputFileName,
                InputRawFileName = signFileRequest.FileToSign.FileName,
                HashAlgorithm = signFileRequest.HashAlgorithm,
                Certificate = certificate.Certificate,
                PrivateKey = certificate.PrivateKey,
                TimestampServer = timestampServer
            });

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

            stopwatch.Stop();
            apiSignFileResponse.SignTimeInMilliseconds = stopwatch.ElapsedMilliseconds;

            _logger.LogInformation(
                $"[{remoteIp}] [Finished] request for file '{signFileRequest.FileToSign.FileName}' finished ({signFileRequest.FileToSign.FileName} bytes, uploaded in {apiSignFileResponse.UploadTimeInMilliseconds}ms, signed in {apiSignFileResponse.SignTimeInMilliseconds})");
        }
        catch (Exception e)
        {
            _logger.LogError(e, $"[{remoteIp}] Signing of '{signFileRequest.FileToSign?.Name}' failed: {e.Message}");
            apiSignFileResponse.Status = SignFileResponseStatus.FileNotSignedError;
            apiSignFileResponse.ErrorMessage = e.Message;
        }

        return new SignFileActionResult(apiSignFileResponse, coreSignFileResponse?.ResultFiles);
    }

    private string RemoteIp => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
