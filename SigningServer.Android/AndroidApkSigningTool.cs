using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ICSharpCode.SharpZipLib.Zip;
using SigningServer.Android.Com.Android.Apksig;
using SigningServer.Android.Com.Android.Apksig.Apk;
using SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1;
using SigningServer.Android.Security.DotNet;
using SigningServer.Core;
using X509Certificate = SigningServer.Android.Security.Cert.X509Certificate;

namespace SigningServer.Android
{
    // "A signed JAR file is exactly the same as the original JAR file, except that its manifest is updated 
    // and two additional files are added to the META-INF directory: a signature file and a signature block file."
    // "For every file entry signed in the signed JAR file, an individual manifest entry is created for it as long as 
    //  it does not already exist in the manifest. Each manifest entry lists one or more digest attributes and an optional Magic attribute."
    // https://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Signed_JAR_File

    public class AndroidApkSigningTool : ISigningTool
    {
        private static readonly Version Version = typeof(AndroidApkSigningTool).Assembly.GetName().Version;
        public static readonly string CreatedBy = Version.ToString(3) + " (SigningServer)";

        private static readonly HashSet<string> ApkSupportedExtension =
            new HashSet<string>(StringComparer.InvariantCultureIgnoreCase) { ".apk", ".aab" };

        private static readonly Dictionary<string, DigestAlgorithm> ApkSupportedHashAlgorithms =
            new Dictionary<string, DigestAlgorithm>(StringComparer.InvariantCultureIgnoreCase)
            {
                ["SHA1"] = DigestAlgorithm.SHA1, ["SHA256"] = DigestAlgorithm.SHA256
            };

        public string FormatName => "Android Application Packages";

        public bool IsFileSupported(string fileName)
        {
            return ApkSupportedExtension.Contains(Path.GetExtension(fileName));
        }

        public async ValueTask<SignFileResponse> SignFileAsync(SignFileRequest signFileRequest,
            CancellationToken cancellationToken)
        {
            var signFileResponse = new SignFileResponse();
            var successResult = SignFileResponseStatus.FileSigned;

            if (await IsFileSignedAsync(signFileRequest.InputFilePath, cancellationToken))
            {
                if (signFileRequest.OverwriteSignature)
                {
                    successResult = SignFileResponseStatus.FileResigned;
                }
                else
                {
                    signFileResponse.Status = SignFileResponseStatus.FileAlreadySigned;
                    return signFileResponse;
                }
            }

            var outputFileName = signFileRequest.InputFilePath + ".signed";
            var outputSignatureFileName = signFileRequest.InputFilePath + ".idsig";
            try
            {
                var name = signFileRequest.Certificate.Value.FriendlyName;
                if (string.IsNullOrEmpty(name))
                {
                    name = signFileRequest.Certificate.Value.SubjectName.Name;
                    if (name?.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        name = name.Substring("CN=".Length);
                    }
                }

                if (string.IsNullOrEmpty(name))
                {
                    name = "sig";
                }

                var signerConfigs = new Collections.List<ApkSigner.SignerConfig>
                {
                    new ApkSigner.SignerConfig(name,
                        DotNetCryptographyProvider.Instance.CreatePrivateKey(signFileRequest.PrivateKey.Value),
                        new Collections.List<X509Certificate>
                        {
                            DotNetCryptographyProvider.Instance.CreateCertificate(signFileRequest.Certificate.Value)
                        }, false)
                };

                var apkSignerBuilder = new ApkSigner.Builder(signerConfigs)
                    .SetInputApk(new FileInfo(signFileRequest.InputFilePath))
                    .SetOutputApk(new FileInfo(outputFileName))
                    .SetOtherSignersSignaturesPreserved(false)
                    .SetV1SigningEnabled(true)
                    .SetV2SigningEnabled(true)
                    .SetV3SigningEnabled(true)
                    .SetV4SigningEnabled(true)
                    .SetForceSourceStampOverwrite(false)
                    .SetVerityEnabled(false)
                    .SetCreatedBy(CreatedBy)
                    .SetV4ErrorReportingEnabled(true)
                    .SetV4SignatureOutputFile(new FileInfo(outputSignatureFileName))
                    .SetDebuggableApkPermitted(true);

                var apkSigner = apkSignerBuilder.Build();
                apkSigner.Sign();

                signFileResponse.Status = successResult;
                signFileResponse.ResultFiles = new List<SignFileResponseFileInfo>
                {
                    new SignFileResponseFileInfo(signFileRequest.OriginalFileName, outputFileName),
                };
                if (File.Exists(outputSignatureFileName))
                {
                    signFileResponse.ResultFiles.Add(
                        new SignFileResponseFileInfo(signFileRequest.OriginalFileName + ".idsig",
                            outputSignatureFileName));
                }

                return signFileResponse;
            }
            catch
            {
                if (File.Exists(outputFileName))
                {
                    File.Delete(outputFileName);
                }

                if (File.Exists(outputSignatureFileName))
                {
                    File.Delete(outputSignatureFileName);
                }

                throw;
            }
        }


        public ValueTask<bool> IsFileSignedAsync(string inputFileName, CancellationToken cancellationToken)
        {
            using var inputJar = new ZipInputStream(new FileStream(inputFileName, FileMode.Open, FileAccess.Read));
            var manifestExists = false;
            var signatureExists = false;
            var signatureBlockExists = false;

            while (inputJar.GetNextEntry() is { } entry)
            {
                if (entry.IsFile)
                {
                    if (ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME.Equals(entry.Name,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        manifestExists = true;
                    }
                    else if (entry.Name.StartsWith("META-INF", StringComparison.OrdinalIgnoreCase))
                    {
                        if (entry.Name.EndsWith(".SF", StringComparison.OrdinalIgnoreCase))
                        {
                            signatureExists = true;
                        }
                        else if (entry.Name.EndsWith(".RSA", StringComparison.OrdinalIgnoreCase))
                        {
                            signatureBlockExists = true;
                        }
                    }
                }

                if (manifestExists && signatureExists && signatureBlockExists)
                {
                    return ValueTask.FromResult(true);
                }
            }

            return ValueTask.FromResult(false);
        }

        /// <inheritdoc />
        public IReadOnlyList<string> SupportedFileExtensions => ApkSupportedExtension.ToArray();

        public IReadOnlyList<string> SupportedHashAlgorithms => ApkSupportedHashAlgorithms.Keys.ToArray();
    }
}
