using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using SigningServer.ClickOnce.MsBuild;
using SigningServer.Contracts;

namespace SigningServer.ClickOnce
{
    public class ClickOnceSigningTool : ISigningTool
    {
        private static readonly HashSet<string> ClickOnceSupportedExtension =
            new(StringComparer.InvariantCultureIgnoreCase) { ".application", ".manifest" };

        private static readonly string[] ClickOnceSupportedHashAlgorithms = { "SHA256" };

        private readonly ILogger<ClickOnceSigningTool> _logger;

        public ClickOnceSigningTool(ILogger<ClickOnceSigningTool> logger)
        {
            _logger = logger;
        }

        public bool IsFileSupported(string fileName)
        {
            return ClickOnceSupportedExtension.Contains(Path.GetExtension(fileName));
        }

        public void SignFile(string inputFileName, X509Certificate2 certificate,
            AsymmetricAlgorithm privateKey,
            string timestampServer,
            SignFileRequest signFileRequest, SignFileResponse signFileResponse)
        {
            var successResult = SignFileResponseResult.FileSigned;

            if (IsFileSigned(inputFileName))
            {
                if (signFileRequest.OverwriteSignature)
                {
                    UnsignFile(inputFileName);
                    successResult = SignFileResponseResult.FileResigned;
                }
                else
                {
                    signFileResponse.Result = SignFileResponseResult.FileAlreadySigned;
                    return;
                }
            }

            SecurityUtilities.SignFile(certificate, privateKey, timestampServer, inputFileName);
            signFileResponse.Result = successResult;
            signFileResponse.FileContent = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
            signFileResponse.FileSize = signFileResponse.FileContent.Length;
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
}
