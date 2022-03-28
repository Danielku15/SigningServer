using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Build.Tasks.Deployment.ManifestUtilities;
using NLog;
using SigningServer.Contracts;

namespace SigningServer.Server.SigningTool
{
    public class ClickOnceSigningTool : ISigningTool
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();

        private static readonly HashSet<string> ClickOnceSupportedExtension =
            new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
            {
                ".application",
                ".manifest"
            };

        private static readonly string[] ClickOnceSupportedHashAlgorithms = { "SHA256" };


        public bool IsFileSupported(string fileName)
        {
            return ClickOnceSupportedExtension.Contains(Path.GetExtension(fileName));
        }

        public void SignFile(string inputFileName, X509Certificate2 certificate, string timestampServer,
            SignFileRequest signFileRequest, SignFileResponse signFileResponse)
        {
            SignFileResponseResult successResult = SignFileResponseResult.FileSigned;

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

            try
            {
                // var manifestDom = new XmlDocument
                // {
                //     PreserveWhitespace = true
                // };
                // manifestDom.Load(inputFileName);
                
                SecurityUtilities.SignFile(certificate, string.IsNullOrEmpty(timestampServer) ? null : new Uri(timestampServer), inputFileName);

                // // https://github.com/dotnet/msbuild/blob/main/src/Tasks/ManifestUtil/SecurityUtil.cs
                // var signedCmiManifest2 = new SignedCmiManifest2(manifestDom);
                // signedCmiManifest2.Sign(certificate.PrivateKey, certificate, timestampServer);
                //
                // manifestDom.Save(inputFileName);

                signFileResponse.Result = successResult;
                signFileResponse.FileContent = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
                signFileResponse.FileSize = signFileResponse.FileContent.Length;
            }
            catch (Exception ex)
            {
                signFileResponse.Result = SignFileResponseResult.FileNotSignedError;
                signFileResponse.ErrorMessage = ex.Message;
                Log.Error($"{inputFileName} signing failed {signFileResponse.ErrorMessage}");
            }
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
                Log.Error(e, "Could not load Click Once Application");
                return false;
            }

            return false;
        }

        public void UnsignFile(string inputFileName)
        {
            var xml = XDocument.Parse(File.ReadAllText(inputFileName), LoadOptions.PreserveWhitespace);
            if (xml.Root != null)
            {
                xml.Root.Elements()
                    .Where(e => e.Name.LocalName == "publisherIdentity" || e.Name.LocalName == "Signature").Remove();
            }

            File.WriteAllText(inputFileName, xml.ToString(SaveOptions.DisableFormatting));
        }

        /// <inheritdoc />
        public string[] SupportedFileExtensions => ClickOnceSupportedExtension.ToArray();

        public string[] SupportedHashAlgorithms => ClickOnceSupportedHashAlgorithms;
    }
}