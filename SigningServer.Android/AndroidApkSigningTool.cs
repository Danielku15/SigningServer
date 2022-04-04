﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using ICSharpCode.SharpZipLib.Zip;
using SigningServer.Android.ApkSig;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Contracts;

namespace SigningServer.Android
{
    // "A signed JAR file is exactly the same as the original JAR file, except that its manifest is updated 
    // and two additional files are added to the META-INF directory: a signature file and a signature block file."
    // "For every file entry signed in the signed JAR file, an individual manifest entry is created for it as long as 
    //  it does not already exist in the manifest. Each manifest entry lists one or more digest attributes and an optional Magic attribute."
    // https://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Signed_JAR_File

    public class AndroidApkSigningTool : ISigningTool
    {
        private static readonly HashSet<string> ApkSupportedExtension =
            new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
            {
                ".jar", ".apk"
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

        public void SignFile(string inputFileName, X509Certificate2 certificate, string timestampServer,
            SignFileRequest signFileRequest, SignFileResponse signFileResponse)
        {
            SignFileResponseResult successResult = SignFileResponseResult.FileSigned;

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
                var digestAlgorithm = DigestAlgorithm.SHA256;
                
                if (string.IsNullOrEmpty(signFileRequest.HashAlgorithm) ||
                    !ApkSupportedHashAlgorithms.TryGetValue(signFileRequest.HashAlgorithm, out digestAlgorithm))
                {
                    digestAlgorithm = DigestAlgorithm.SHA256;
                }

                var isAndroidSigningEnabled =
                        !".jar".Equals(Path.GetExtension(inputFileName),
                            StringComparison.InvariantCultureIgnoreCase) && // v2 only for APKs not for JARs
                        (!digestAlgorithm.Equals(DigestAlgorithm.SHA1)) // v2 signing requires SHA256 or SHA512
                    ;

                var signerConfigs = new List<ApkSigner.SignerConfig>
                {
                    new ApkSigner.SignerConfig(certificate.FriendlyName,
                        new PrivateKey(certificate.PrivateKey),
                        new List<X509Certificate>
                        {
                            new WrappedX509Certificate(certificate)
                        }, false)
                };

                ApkSigner.Builder apkSignerBuilder = new ApkSigner.Builder(signerConfigs)
                    .setInputApk(new FileInfo(inputFileName))
                    .setOutputApk(new FileInfo(outputFileName))
                    .setOtherSignersSignaturesPreserved(true)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(isAndroidSigningEnabled)
                    .setV3SigningEnabled(isAndroidSigningEnabled)
                    .setV4SigningEnabled(isAndroidSigningEnabled)
                    .setForceSourceStampOverwrite(false)
                    .setVerityEnabled(false)
                    .setV4ErrorReportingEnabled(isAndroidSigningEnabled)
                    .setDebuggableApkPermitted(true)
                    .setDigestAlgorithm(digestAlgorithm);

                ApkSigner apkSigner = apkSignerBuilder.build();
                apkSigner.sign();

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
            using (var inputJar = new ZipFile(inputFileName))
            {
                var manifestExists = false;
                var signatureExists = false;
                var signatureBlockExists = false;

                foreach (var entry in inputJar.OfType<ZipEntry>())
                {
                    if (entry.IsFile)
                    {
                        if (ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME.Equals(entry.Name, StringComparison.OrdinalIgnoreCase) )
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
        }

        /// <inheritdoc />
        public string[] SupportedFileExtensions => ApkSupportedExtension.ToArray();

        public string[] SupportedHashAlgorithms => ApkSupportedHashAlgorithms.Keys.ToArray();
    }
}