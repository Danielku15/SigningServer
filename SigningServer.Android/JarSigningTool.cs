using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ICSharpCode.SharpZipLib.Zip;
using SigningServer.Android.Com.Android.Apksig;
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

    public class JarSigningTool : ISigningTool
    {
        private static readonly HashSet<string> JarSupportedExtension =
            new HashSet<string>(StringComparer.InvariantCultureIgnoreCase) { ".jar", ".aab" };

        private static readonly Dictionary<string, DigestAlgorithm> JarSupportedHashAlgorithms =
            new Dictionary<string, DigestAlgorithm>(StringComparer.InvariantCultureIgnoreCase)
            {
                ["SHA1"] = DigestAlgorithm.SHA1, 
                ["SHA256"] = DigestAlgorithm.SHA256
            };

        public string FormatName => "Java Applications";

        public bool IsFileSupported(string fileName)
        {
            return JarSupportedExtension.Contains(Path.GetExtension(fileName));
        }

        public async ValueTask<SignFileResponse> SignFileAsync(SignFileRequest signFileRequest,
            CancellationToken cancellationToken)
        {
            var successResult = SignFileResponseStatus.FileSigned;

            if (await IsFileSignedAsync(signFileRequest.InputFilePath, cancellationToken))
            {
                if (signFileRequest.OverwriteSignature)
                {
                    successResult = SignFileResponseStatus.FileResigned;
                }
                else
                {
                    return SignFileResponse.FileAlreadySignedError;
                }
            }

            var outputFileName = signFileRequest.InputFilePath + ".signed";
            var cerificate = await signFileRequest.Certificate.Value;
            var privateKey = await signFileRequest.PrivateKey.Value;
            try
            {
                var name = cerificate.FriendlyName;
                if (string.IsNullOrEmpty(name))
                {
                    name = cerificate.SubjectName.Name;
                    if (name.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
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
                        DotNetCryptographyProvider.Instance.CreatePrivateKey(privateKey),
                        new Collections.List<X509Certificate>
                        {
                            DotNetCryptographyProvider.Instance.CreateCertificate(cerificate)
                        }, false)
                };

                if (!JarSupportedHashAlgorithms.TryGetValue(signFileRequest.HashAlgorithm ?? "",
                        out var digestAlgorithm))
                {
                    digestAlgorithm = DigestAlgorithm.SHA256;
                }

                // We use some internals of the APK signer to perform the JAR signing. 
                var apkSignerBuilder = new ApkSigner.Builder(new JarSignerEngine(signerConfigs, digestAlgorithm))
                    .SetInputApk(new FileInfo(signFileRequest.InputFilePath))
                    .SetOutputApk(new FileInfo(outputFileName));
                var apkSigner = apkSignerBuilder.Build();
                apkSigner.Sign();

                return new SignFileResponse(successResult, string.Empty,
                    new[] { new SignFileResponseFileInfo(signFileRequest.OriginalFileName, outputFileName), });
            }
            catch
            {
                if (File.Exists(outputFileName))
                {
                    File.Delete(outputFileName);
                }

                throw;
            }
        }


        public ValueTask<bool> IsFileSignedAsync(string inputFileName, CancellationToken cancellationToken)
        {
            using var inputJar = new ZipInputStream(new FileStream(inputFileName, FileMode.Open, FileAccess.Read));
            // Android manifest does not need to exist if we have a jar
            var signatureExists = false;
            var signatureBlockExists = false;

            while (inputJar.GetNextEntry() is { } entry)
            {
                if (entry.IsFile)
                {
                    if (entry.Name.StartsWith("META-INF", StringComparison.OrdinalIgnoreCase))
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

                if (signatureExists && signatureBlockExists)
                {
                    return ValueTask.FromResult(true);
                }
            }

            return ValueTask.FromResult(false);
        }

        /// <inheritdoc />
        public IReadOnlyList<string> SupportedFileExtensions => JarSupportedExtension.ToArray();

        public IReadOnlyList<string> SupportedHashAlgorithms => JarSupportedHashAlgorithms.Keys.ToArray();
    }
}
