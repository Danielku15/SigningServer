using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using SigningServer.ClickOnce.MsBuild;
using SigningServer.Core;

namespace SigningServer.ClickOnce;

public class ClickOnceSigningTool : ISigningTool
{
    private static readonly HashSet<string> ClickOnceSupportedExtension =
        new(StringComparer.InvariantCultureIgnoreCase) { ".application", ".manifest" };

    private static readonly string[] ClickOnceSupportedHashAlgorithms = { "SHA256" };

    private readonly ILogger<ClickOnceSigningTool> _logger;

    public string FormatName => "Microsoft ClickOnce";

    public ClickOnceSigningTool(ILogger<ClickOnceSigningTool> logger)
    {
        _logger = logger;
    }

    public bool IsFileSupported(string fileName)
    {
        return ClickOnceSupportedExtension.Contains(Path.GetExtension(fileName));
    }

    public async ValueTask<SignFileResponse> SignFileAsync(SignFileRequest signFileRequest, CancellationToken cancellationToken)
    {
        var signFileResponse = new SignFileResponse();
        var successResult = SignFileResponseStatus.FileSigned;

        if (await IsFileSignedAsync(signFileRequest.InputFilePath, cancellationToken))
        {
            if (signFileRequest.OverwriteSignature)
            {
                UnsignFile(signFileRequest.InputFilePath);
                successResult = SignFileResponseStatus.FileResigned;
            }
            else
            {
                signFileResponse.Status = SignFileResponseStatus.FileAlreadySigned;
                return signFileResponse;
            }
        }

        SecurityUtilities.SignFile(signFileRequest.Certificate, signFileRequest.PrivateKey,
            signFileRequest.TimestampServer, signFileRequest.InputFilePath);
        signFileResponse.Status = successResult;
        signFileResponse.ResultFiles = new[]
        {
            new SignFileResponseFileInfo(signFileRequest.OriginalFileName, signFileRequest.InputFilePath)
        };
        return signFileResponse;
    }


    public ValueTask<bool> IsFileSignedAsync(string inputFileName, CancellationToken cancellationToken)
    {
        try
        {
            var xml = XDocument.Parse(File.ReadAllText(inputFileName), LoadOptions.PreserveWhitespace);
            if (xml.Root == null)
            {
                return ValueTask.FromResult(false);
            }

            if (xml.Root.Elements().Any(e => e.Name.LocalName == "Signature"))
            {
                return ValueTask.FromResult(true);
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Could not load Click Once Application");
            return ValueTask.FromResult(false);
        }

        return ValueTask.FromResult(false);
    }

    public void UnsignFile(string inputFileName)
    {
        var xml = XDocument.Parse(File.ReadAllText(inputFileName), LoadOptions.PreserveWhitespace);
        xml.Root?.Elements()
            .Where(e => e.Name.LocalName is "publisherIdentity" or "Signature")
            .Remove();

        File.WriteAllText(inputFileName, xml.ToString(SaveOptions.DisableFormatting));
    }

    /// <inheritdoc />
    public IReadOnlyList<string> SupportedFileExtensions => ClickOnceSupportedExtension.ToArray();

    public IReadOnlyList<string> SupportedHashAlgorithms => ClickOnceSupportedHashAlgorithms;
}
