using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

    public string Name => "Microsoft ClickOnce";

    public ClickOnceSigningTool(ILogger<ClickOnceSigningTool> logger)
    {
        _logger = logger;
    }

    public bool IsFileSupported(string fileName)
    {
        return ClickOnceSupportedExtension.Contains(Path.GetExtension(fileName));
    }

    public SignFileResponse SignFile(SignFileRequest signFileRequest)
    {
        var signFileResponse = new SignFileResponse();
        var successResult = SignFileResponseStatus.FileSigned;

        if (IsFileSigned(signFileRequest.InputFilePath))
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
            new SignFileResponseFileInfo(signFileRequest.InputRawFileName, signFileRequest.InputFilePath)
        };
        return signFileResponse;
    }


    public bool IsFileSigned(string inputFileName)
    {
        try
        {
            var xml = XDocument.Parse(File.ReadAllText(inputFileName), LoadOptions.PreserveWhitespace);
            if (xml.Root == null)
            {
                return false;
            }

            if (xml.Root.Elements().Any(e => e.Name.LocalName == "Signature"))
            {
                return true;
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Could not load Click Once Application");
            return false;
        }

        return false;
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
    public string[] SupportedFileExtensions => ClickOnceSupportedExtension.ToArray();

    public string[] SupportedHashAlgorithms => ClickOnceSupportedHashAlgorithms;
}
