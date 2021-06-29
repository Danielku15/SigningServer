using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.Build.Tasks.Deployment.ManifestUtilities;
using NLog;
using SigningServer.Contracts;
using DWORD = System.UInt32;

namespace SigningServer.Server.SigningTool
{
    public class PowerShellSigningTool : ISigningTool
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();

        private static readonly HashSet<string> PowerShellSupportedExtension =
            new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
            {
                ".ps1",
                ".psm1"
            };

        private static readonly string[] PowerShellSupportedHashAlgorithms = { "SHA256" };


        public bool IsFileSupported(string fileName)
        {
            return PowerShellSupportedExtension.Contains(Path.GetExtension(fileName));
        }

        public void SignFile(string inputFileName, X509Certificate2 certificate, string timestampServer,
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


            SignatureHelper.SignFile(SigningOption.Default, inputFileName, certificate, timestampServer, signFileRequest.HashAlgorithm);

            signFileResponse.Result = successResult;
            signFileResponse.FileContent = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
            signFileResponse.FileSize = signFileResponse.FileContent.Length;
        }

        public bool IsFileSigned(string inputFileName)
        {
            var script = File.ReadAllLines(inputFileName);
            foreach (var line in script)
            {
                if (line.StartsWith("# SIG # Begin"))
                {
                    return true;
                }
            }
            return false;
        }

        public void UnsignFile(string inputFileName)
        {
            var script = File.ReadAllLines(inputFileName);
            using (var writer = new StreamWriter(new FileStream(inputFileName, FileMode.Create)))
            {
                var isSignatureBlock = false;
                foreach (var line in script)
                {
                    if (line.StartsWith("# SIG # Begin"))
                    {
                        isSignatureBlock = true;
                    }
                    else if (line.StartsWith("# SIG # End"))
                    {
                        isSignatureBlock = false;
                    }
                    else if (!isSignatureBlock)
                    {
                        writer.WriteLine(line);
                    }
                }
            }
        }

        /// <inheritdoc />
        public string[] SupportedFileExtensions => PowerShellSupportedExtension.ToArray();

        public string[] SupportedHashAlgorithms => PowerShellSupportedHashAlgorithms;
    }
}