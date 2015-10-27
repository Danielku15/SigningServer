using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using ICSharpCode.SharpZipLib.Zip;
using NLog;
using Org.BouncyCastle.Tsp;
using SigningServer.Contracts;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace SigningServer.Server.SigningTool
{
    // "A signed JAR file is exactly the same as the original JAR file, except that its manifest is updated 
    // and two additional files are added to the META-INF directory: a signature file and a signature block file."
    // "For every file entry signed in the signed JAR file, an individual manifest entry is created for it as long as 
    //  it does not already exist in the manifest. Each manifest entry lists one or more digest attributes and an optional Magic attribute."
    // https://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Signed_JAR_File

    public class AndroidApkSigningTool : ISigningTool
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();

        private const string ManifestName = "META-INF/MANIFEST.MF";
        private const string SignatureName = "META-INF/CERT.SF";
        private const string SignatureBlockName = "META-INF/CERT.";
        private const string MetaInf = "META-INF/";

        private static readonly string CreatedBy = typeof(AndroidApkSigningTool).Assembly.GetName().Version +
                                                   " (CoderLine SigningServer)";

        private static readonly Random Random = new Random();

        private static readonly HashSet<string> SupportedExtension = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
        {
            ".jar",  ".apk"
        };

        public bool IsFileSupported(string fileName)
        {
            return SupportedExtension.Contains(Path.GetExtension(fileName));
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

            var outputFileName = inputFileName + ".signed";
            try
            {
                using (var hasher = new SHA256Managed())
                {
                    using (var inputJar = new ZipFile(inputFileName))
                    {
                        using (var outputJar = ZipFile.Create(outputFileName))
                        {
                            outputJar.BeginUpdate();

                            var manifest = CreateSignedManifest(inputJar, outputJar, hasher);

                            var signatureFile = CreateSignatureFile(outputJar, manifest);

                            CreateSignatureBlockFile(outputJar, certificate, signatureFile, timestampServer);

                            foreach (var entry in inputJar.OfType<ZipEntry>())
                            {
                                Log.Trace($"Cloning file ${entry.Name} into new zip");
                                outputJar.Add(new ZipEntryDataSource(inputJar, entry), entry.Name);
                            }

                            outputJar.CommitUpdate();
                            outputJar.Close();
                        }
                    }

                    File.Delete(inputFileName);
                    File.Move(outputFileName, inputFileName);

                    signFileResponse.Result = successResult;
                    signFileResponse.FileContent = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
                    signFileResponse.FileSize = signFileResponse.FileContent.Length;
                }
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

        private static readonly Oid DataOid = new Oid("1.2.840.113549.1.7.1");
        private static readonly Oid SignatureTimestampTokenOid = new Oid("1.2.840.113549.1.9.16.2.14");

        private void CreateSignatureBlockFile(ZipFile outputJar, X509Certificate2 certificate, byte[] signatureFileData, string timestampServer)
        {
            Log.Trace("Creating Signature Block File");

            try
            {
                // "A digital signature is a signed version of the .SF signature file. These are binary files not intended to be interpreted by humans."

                // Digital signature files have the same filenames as the .SF files but different extensions. The extension varies depending on the type of digital signature.
                var fileName = SignatureBlockName;
                Func<byte[], byte[]> signData;
                if (certificate.PrivateKey is RSACryptoServiceProvider)
                {
                    fileName += "RSA";
                    signData = data =>
                    {
                        using (var sha1Provider = new SHA1CryptoServiceProvider())
                        {
                            return ((RSACryptoServiceProvider)certificate.PrivateKey).SignData(data, sha1Provider);
                        }
                    };
                }
                else if (certificate.PrivateKey is DSACryptoServiceProvider)
                {
                    fileName += "DSA";
                    signData = data => ((DSACryptoServiceProvider)certificate.PrivateKey).SignData(data);
                }
                else
                {
                    throw new InvalidOperationException("Unsupported certificate");
                }

                CmsSigner signer;
                Uri timestampUri;
                if (Uri.TryCreate(timestampServer, UriKind.Absolute, out timestampUri))
                {
                    Log.Trace("Signing signature file");
                    var signature = signData(signatureFileData);
                    signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate);
                    signer.UnsignedAttributes.Add(new Pkcs9AttributeObject(SignatureTimestampTokenOid, GenerateTimestampToken(signature, timestampUri)));
                }
                else
                {
                    signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate);
                }

                var content = new ContentInfo(DataOid, signatureFileData);
                var signedCms = new SignedCms(content, true);
                signedCms.ComputeSignature(signer);
                outputJar.Add(new StreamDataSource(new MemoryStream(signedCms.Encode())), fileName);

                Log.Trace("Certificate block file written");
            }
            catch (Exception e)
            {
                Log.Error(e, "Certificate block file writing failed");
                throw;
            }
        }

        private byte[] GenerateTimestampToken(byte[] signature, Uri timestampUri)
        {
            Log.Trace($"Timestamping with server: ${timestampUri}");
            var request = WebRequest.CreateHttp(timestampUri);
            request.ContentType = "application/timestamp-query";
            request.Method = "POST";
            request.Timeout = 15000;

            var timeStampRequestGenerator = new TimeStampRequestGenerator();
            timeStampRequestGenerator.SetCertReq(true);
            using (var hasher = new SHA1Managed())
            {
                signature = hasher.ComputeHash(signature);
            }
            var timestampRequest = timeStampRequestGenerator.Generate(TspAlgorithms.Sha1, signature, new BigInteger(64, Random));
            var timestampRequestRaw = timestampRequest.GetEncoded();
            request.ContentLength = timestampRequestRaw.Length;

            using (var requestStream = request.GetRequestStream())
            {
                requestStream.Write(timestampRequestRaw, 0, timestampRequestRaw.Length);
            }

            using (var response = request.GetResponse())
            {
                var responseStream = response.GetResponseStream();
                if (responseStream == null)
                {
                    throw new IOException("Timestmap server did not contain any response data");
                }

                using (var bufferedResponseStream = new BufferedStream(responseStream))
                {
                    var timestampResponse = new TimeStampResponse(bufferedResponseStream);
                    timestampResponse.Validate(timestampRequest);
                    Log.Trace("Timestamping done");
                    return timestampResponse.TimeStampToken.GetEncoded();
                }
            }
        }

        private byte[] CreateSignatureFile(ZipFile outputJar, Manifest manifest)
        {
            try
            {
                Log.Trace("Creating CERT.SF");
                var signatureFile = new Manifest();
                signatureFile.MainSection.Name = "Signature-Version";
                signatureFile.MainSection.Value = "1.0";
                signatureFile.MainSection.Add(new ManifestEntry("SHA-256-Digest-Manifest-Main-Attributes", manifest.MainSection.Sha256Digest));
                signatureFile.MainSection.Add(new ManifestEntry("SHA-256-Digest-Manifest", manifest.Sha256Digest));
                signatureFile.MainSection.Add(new ManifestEntry("Created-By", CreatedBy));

                foreach (var additionalSection in manifest.AdditionalSections)
                {
                    Log.Trace($"creating entry for ${additionalSection.Value.Value}");
                    var signatureSection = new ManifestSection
                    {
                        Name = additionalSection.Value.Name,
                        Value = additionalSection.Value.Value
                    };
                    signatureSection.Add(new ManifestEntry("SHA-256-Digest", additionalSection.Value.Sha256Digest));
                    signatureFile.AdditionalSections[signatureSection.Value] = signatureSection;
                }

                var signatureData = new MemoryStream();
                signatureFile.Write(signatureData);

                var signatureDataRaw = signatureData.ToArray();
                outputJar.Add(new StreamDataSource(new MemoryStream(signatureDataRaw)), SignatureName);

                Log.Trace("CERT.SF created");

                return signatureDataRaw;
            }
            catch (Exception e)
            {
                Log.Error(e, "CERT.SF creation failed");
                throw;
            }
        }

        private Manifest CreateSignedManifest(ZipFile inputJar, ZipFile outputJar, HashAlgorithm hasher)
        {
            Log.Trace("Creating MANIFEST.MF");
            try
            {
                var newManifest = new Manifest();
                var existingManifest = inputJar.GetEntry(ManifestName);
                if (existingManifest != null)
                {
                    Log.Trace("Found existing manifest, importing it");
                    using (var s = inputJar.GetInputStream(existingManifest))
                    {
                        newManifest.Read(s);
                    }
                }
                else
                {
                    Log.Trace("No manifest found in jar, create a new one");
                    newManifest.MainSection.Name = "Manifest-Version";
                    newManifest.MainSection.Value = "1.0";
                    newManifest.MainSection.Add(new ManifestEntry("Created-By", CreatedBy));
                }

                // compute file digests for manifest
                foreach (var entry in inputJar.OfType<ZipEntry>())
                {
                    if (IsSignatureRelated(entry))
                    {
                        Log.Trace($"creating manifest entry for {entry.Name}");

                        ManifestSection section;
                        if (!newManifest.AdditionalSections.TryGetValue(entry.Name, out section))
                        {
                            section = new ManifestSection
                            {
                                Name = "Name",
                                Value = entry.Name
                            };
                            newManifest.AdditionalSections[section.Value] = section;
                        }
                        else
                        {
                            // remove existing digest
                            section.RemoveAll(e => e.Key == "SHA-256-Digest");
                        }

                        section.Add(new ManifestEntry("SHA-256-Digest", HashEntry(inputJar, entry, hasher)));
                    }
                }

                var manifestData = new MemoryStream();
                newManifest.Write(manifestData);
                manifestData.Seek(0, SeekOrigin.Begin);
                outputJar.Add(new StreamDataSource(manifestData), ManifestName);

                Log.Trace("manifest created");

                return newManifest;
            }
            catch (Exception e)
            {
                Log.Error(e, "Manifest creation failed");
                throw;
            }
        }

        private string HashEntry(ZipFile inputJar, ZipEntry entry, HashAlgorithm hasher)
        {
            using (var s = inputJar.GetInputStream(entry))
            {
                hasher.Initialize();
                return Convert.ToBase64String(hasher.ComputeHash(s));
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
                        if (entry.Name == ManifestName)
                        {
                            manifestExists = true;
                        }
                        else if (entry.Name.StartsWith(MetaInf, StringComparison.InvariantCultureIgnoreCase))
                        {
                            if (entry.Name.EndsWith(".SF", StringComparison.InvariantCultureIgnoreCase))
                            {
                                signatureExists = true;
                            }
                            else if (entry.Name.EndsWith(".RSA", StringComparison.InvariantCultureIgnoreCase))
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

        public void UnsignFile(string inputFileName)
        {
            var outputFileName = inputFileName + ".unsigned";
            try
            {
                using (var inputJar = new ZipFile(inputFileName))
                {
                    using (var outputJar = ZipFile.Create(outputFileName))
                    {
                        outputJar.BeginUpdate();

                        foreach (var entry in inputJar.OfType<ZipEntry>())
                        {
                            if (IsSignatureRelated(entry) ||
                                entry.Name.Equals(ManifestName, StringComparison.InvariantCultureIgnoreCase))
                            {
                                outputJar.Add(new ZipEntryDataSource(inputJar, entry), entry.Name);
                            }
                        }

                        outputJar.CommitUpdate();
                        outputJar.Close();
                    }
                }

                File.Delete(inputFileName);
                File.Move(outputFileName, inputFileName);
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

        private static bool IsSignatureRelated(ZipEntry entry)
        {
            // https://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#SignedJar-Overview
            if (!entry.IsFile)
            {
                return false;
            }

            if (entry.Name.Equals(ManifestName, StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            if (entry.Name.StartsWith(MetaInf, StringComparison.InvariantCultureIgnoreCase) &&
                entry.Name.EndsWith(".SF", StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            if (entry.Name.StartsWith(MetaInf, StringComparison.InvariantCultureIgnoreCase) &&
                entry.Name.EndsWith(".RSA", StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            if (entry.Name.StartsWith(MetaInf, StringComparison.InvariantCultureIgnoreCase) &&
                entry.Name.EndsWith(".DSA", StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            return false;
        }

        public string[] GetSupportedFileExtensions()
        {
            return SupportedExtension.ToArray();
        }

        private class ZipEntryDataSource : IStaticDataSource
        {
            private readonly ZipFile _zipFile;
            private readonly ZipEntry _zipEntry;

            public ZipEntryDataSource(ZipFile zipFile, ZipEntry zipEntry)
            {
                _zipFile = zipFile;
                _zipEntry = zipEntry;
            }

            public Stream GetSource()
            {
                return _zipFile.GetInputStream(_zipEntry);
            }
        }

        private class StreamDataSource : IStaticDataSource
        {
            private readonly Stream _source;

            public StreamDataSource(Stream source)
            {
                _source = source;
            }

            public Stream GetSource()
            {
                _source.Seek(0, SeekOrigin.Begin);
                return _source;
            }
        }
    }
}