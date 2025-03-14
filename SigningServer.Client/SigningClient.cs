using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using SigningServer.ClientCore;
using SigningServer.Core;
using SigningServer.Dtos;

namespace SigningServer.Client;

public class SigningClient : SigningClient<SigningClientConfiguration>
{
    private readonly HttpClient _client;

    public SigningClient(SigningClientConfiguration configuration, ILogger<SigningClient> logger) : base(configuration,
        logger)
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

        var timeout = TimeSpan.FromSeconds(configuration.Timeout > 0 ? configuration.Timeout : 60);
        _client = new HttpClient { BaseAddress = signingServerUri, Timeout = timeout };
    }

    public SigningClient(HttpClient client, ILogger<SigningClient> logger, params string[] sources)
        : base(new SigningClientConfiguration { Sources = sources }, logger)
    {
        _client = client;
    }


    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _client.Dispose();
        }
    }

    protected override async Task<SignHashResponseDto> SignHashAsync(byte[] hashBytes,
        CancellationToken cancellationToken)
    {
        var response = await _client.PostAsJsonAsync("signing/signhash",
            new SignHashRequestDto
            {
                Username = Configuration.Username,
                Password = Configuration.Password,
                HashAlgorithm = Configuration.HashAlgorithm!,
                Hash = Convert.ToBase64String(hashBytes),
                PaddingMode = Configuration.RsaSignaturePaddingMode
            }, DtoJsonSerializerContext.Default.SignHashRequestDto, cancellationToken);

        var responseDto =
            await response.Content.ReadFromJsonAsync<SignHashResponseDto>(
                DtoJsonSerializerContext.Default.SignHashResponseDto,
                cancellationToken: cancellationToken);
        if (responseDto == null)
        {
            throw response.StatusCode switch
            {
                HttpStatusCode.OK => new InvalidOperationException("No response body"),
                HttpStatusCode.BadRequest => new UnsupportedFileFormatException(),
                HttpStatusCode.InternalServerError => new InvalidOperationException("Unknown internal error"),
                HttpStatusCode.Unauthorized => new UnauthorizedAccessException(),
                HttpStatusCode.AlreadyReported => new InvalidOperationException("No response body"),
                _ => new InvalidOperationException("Unknown error, status code: " + response.StatusCode)
            };
        }

        return responseDto;
    }


    protected override async Task<LoadCertificateResponseDto> LoadCertificateAsync(CancellationToken cancellationToken)
    {
        var response = await _client.PostAsJsonAsync("signing/loadcertificate",
            new LoadCertificateRequestDto
            {
                Username = Configuration.Username,
                Password = Configuration.Password,
                ExportFormat = Configuration.LoadCertificateExportFormat!.Value,
                IncludeChain = Configuration.LoadCertificateChain
            }, DtoJsonSerializerContext.Default.LoadCertificateRequestDto, cancellationToken);

        var responseDto =
            await response.Content.ReadFromJsonAsync<LoadCertificateResponseDto>(
                DtoJsonSerializerContext.Default.LoadCertificateResponseDto,
                cancellationToken: cancellationToken);
        if (responseDto == null)
        {
            throw response.StatusCode switch
            {
                HttpStatusCode.OK => new InvalidOperationException("No response body"),
                HttpStatusCode.BadRequest => new UnsupportedFileFormatException(),
                HttpStatusCode.InternalServerError => new InvalidOperationException("Unknown internal error"),
                HttpStatusCode.Unauthorized => new UnauthorizedAccessException(),
                HttpStatusCode.AlreadyReported => new InvalidOperationException("No response body"),
                _ => new InvalidOperationException("Unknown error, status code: " + response.StatusCode)
            };
        }

        return responseDto;
    }

    protected override async IAsyncEnumerable<SignFilePartialResult> SignFileAsync(string file,
        [EnumeratorCancellation] CancellationToken cancellationToken,
        CancellationToken fileCompletedToken)
    {
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
            content.Add(new StreamContent(fs, 10 * 1024 * 1024), "FileToSign", Path.GetFileName(file));
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

            while (await reader.ReadNextSectionAsync(cancellationToken) is { } section)
            {
                if (section.Headers == null ||
                    !section.Headers.TryGetValue("Content-Disposition", out var contentDispositionValue))
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
                        if (!Enum.TryParse(statusValue, true, out SignFileResponseStatus status))
                        {
                            status = SignFileResponseStatus.FileSigned;
                            Logger.LogWarning("Unknown status value: {status}. Ignoring and trying to proceed",
                                statusValue);
                        }

                        yield return new SignFilePartialResult(SignFilePartialResultKind.Status, status);

                        break;
                    case "errormessage":
                        yield return new SignFilePartialResult(SignFilePartialResultKind.ErrorMessage,
                            await ReadAsStringAsync(section.Body));
                        break;
                    case "uploadtimeinmilliseconds":
                        var uploadTimeValue = await ReadAsStringAsync(section.Body);
                        if (long.TryParse(uploadTimeValue, out var uploadTimeInMilliseconds))
                        {
                            yield return new SignFilePartialResult(SignFilePartialResultKind.UploadTime,
                                TimeSpan.FromMilliseconds(uploadTimeInMilliseconds));
                        }
                        else
                        {
                            Logger.LogWarning("Could not parse upload time: {time}", uploadTimeValue);
                        }

                        break;
                    case "signtimeinmilliseconds":
                        var signTimeValue = await ReadAsStringAsync(section.Body);
                        if (long.TryParse(signTimeValue, out var signTimeInMilliseconds))
                        {
                            yield return new SignFilePartialResult(SignFilePartialResultKind.SignTime,
                                TimeSpan.FromMilliseconds(signTimeInMilliseconds));
                        }
                        else
                        {
                            Logger.LogWarning("Could not parse sign time: {time}", signTimeValue);
                        }

                        break;

                    case "resultfiles":
                        yield return new SignFilePartialResult(SignFilePartialResultKind.ResultFile,
                            new SignFileFileResult(fileName, section.Body));
                        break;
                    default:
                        Logger.LogWarning("Unknown response value: {name}, ignoring data", contentDisposition.Name);
                        break;
                }
            }
        }
    }

    private static readonly Regex BoundaryRegex =
        new("boundary=([^,]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static bool TryParseBoundary(string contentType, [NotNullWhen(true)] out string? boundary)
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
        await using (sectionBody)
        {
            using var ms = new MemoryStream();
            await sectionBody.CopyToAsync(ms);
            return Encoding.UTF8.GetString(ms.ToArray());
        }
    }


    public override async Task InitializeAsync()
    {
        Logger.LogInformation("Connecting to signing server");
        ServerCapabilities = await _client.GetFromJsonAsync<ServerCapabilitiesResponse>("signing/capabilities",
                                 DtoJsonSerializerContext.Default.ServerCapabilitiesResponse) ??
                             throw new IOException("No signing capabilities provided by server");
        Logger.LogInformation("Server Capabilities loaded");

        Logger.LogTrace("Supported Formats:");
        foreach (var supportedFormat in ServerCapabilities.SupportedFormats)
        {
            Logger.LogTrace($"  {supportedFormat.Name}");
            Logger.LogTrace("    Supported Extensions: {fileExtensions}",
                string.Join(", ", supportedFormat.SupportedFileExtensions));
            Logger.LogTrace("    Supported Hash Algorithms: {hashAlgorithms}",
                string.Join(", ", supportedFormat.SupportedHashAlgorithms));
            foreach (var extension in supportedFormat.SupportedFileExtensions)
            {
                SupportedFileFormats.Add(extension);
            }
        }
    }
}
