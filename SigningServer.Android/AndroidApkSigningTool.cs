using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ICSharpCode.SharpZipLib.Zip;
using SigningServer.Android.Com.Android.Apksig;
using SigningServer.Android.Com.Android.Apksig.Apk;
using SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1;
using SigningServer.Android.Security.DotNet;
using SigningServer.Contracts;
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
        public static readonly Version Version = typeof(AndroidApkSigningTool).Assembly.GetName().Version;
        public static readonly string CreatedBy = Version.ToString(3) + " (SigningServer)";
        private static readonly HashSet<string> ApkSupportedExtension =
            new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
            {
                ".apk", ".aab"
            };

        private static readonly Dictionary<string, DigestAlgorithm> ApkSupportedHashAlgorithms =
            new Dictionary<string, DigestAlgorithm>(StringComparer.InvariantCultureIgnoreCase)
            {
                ["SHA1"] = DigestAlgorithm.SHA1,
                ["SHA256"] = DigestAlgorithm.SHA256
            };

        public bool IsFileSupported(string fileName)
        {
            return ApkSupportedExtension.Contains(Path.GetExtension(fileName));
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
                    successResult = SignFileResponseResult.FileResigned;
                }
                else
                {
                    signFileResponse.Result = SignFileResponseResult.FileAlreadySigned;
                    return;
                }
            }

            var outputFileName = inputFileName + ".signed";
            try
            {
                var name = certificate.FriendlyName;
                if (string.IsNullOrEmpty(name))
                {
                    name = certificate.SubjectName.Name;
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
                        DotNetCryptographyProvider.INSTANCE.CreatePrivateKey(privateKey),
                        new Collections.List<X509Certificate>
                        {
                            DotNetCryptographyProvider.INSTANCE.CreateCertificate(certificate)
                        }, false)
                };

                var apkSignerBuilder = new ApkSigner.Builder(signerConfigs)
                        .SetInputApk(new FileInfo(inputFileName))
                        .SetOutputApk(new FileInfo(outputFileName))
                        .SetOtherSignersSignaturesPreserved(false)
                        .SetV1SigningEnabled(true)
                        .SetV2SigningEnabled(true)
                        .SetV3SigningEnabled(true)
                        .SetV4SigningEnabled(false) // TODO: no way to transport idsig file to client
                        .SetForceSourceStampOverwrite(false)
                        .SetVerityEnabled(false)
                        .SetCreatedBy(CreatedBy)
                        .SetV4ErrorReportingEnabled(false) // TOOD: v4 support for signing server
                        .SetDebuggableApkPermitted(true);

                var apkSigner = apkSignerBuilder.Build();
                apkSigner.Sign();

                File.Delete(inputFileName);
                File.Move(outputFileName, inputFileName);

                signFileResponse.Result = successResult;
                signFileResponse.FileContent = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
                signFileResponse.FileSize = signFileResponse.FileContent.Length;
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


        public bool IsFileSigned(string inputFileName)
        {
            using var inputJar = new ZipInputStream(new FileStream(inputFileName, FileMode.Open, FileAccess.Read));
            // Android manifest does not need to exist if we have a jar
            var manifestExists = Path.GetExtension(inputFileName) == ".jar";
            var signatureExists = false;
            var signatureBlockExists = false;

            ZipEntry entry;
            while ((entry = inputJar.GetNextEntry()) != null)
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
                    return true;
                }
            }

            return false;
        }

        /// <inheritdoc />
        public string[] SupportedFileExtensions => ApkSupportedExtension.ToArray();

        public string[] SupportedHashAlgorithms => ApkSupportedHashAlgorithms.Keys.ToArray();
    }
}