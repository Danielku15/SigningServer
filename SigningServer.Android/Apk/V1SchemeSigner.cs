/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2018 Daniel Kuschny (C# port based on oreo-master)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SigningServer.Android.Apk.Manifest;
using SigningServer.Android.Crypto;

namespace SigningServer.Android.Apk
{
    /// <summary>
    /// APK signer which uses JAR signing (aka v1 signing scheme).
    /// <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File">Signed JAR File</a>
    /// </summary>
    class V1SchemeSigner
    {
        public const string ManifestEntryName = "META-INF/MANIFEST.MF";

        private const string AttributeValueManifestVersion = "1.0";
        private const string AttributeValueSignatureVersion = "1.0";

        private const string SfAttributeNameAndroidApkSignedName = "X-Android-APK-Signed";
        private const string AttributeNameCreatedBy = ("Created-By");

        private static readonly Oid DataOid = new Oid("1.2.840.113549.1.7.1");

        /// <summary>
        /// Signer configuration.
        /// </summary>
        public class SignerConfig
        {
            public string Name { get; set; }
            public X509Certificate2 Certificate { get; set; }
            public DigestAlgorithm SignatureDigestAlgorithm { get; set; }
        }

        /// <summary>
        /// Returns the names of JAR entries which this signer will produce as part of v1 signature.
        /// </summary>
        /// <param name="signerConfig"></param>
        /// <param name="minSdkVersion"></param>
        /// <returns></returns>
        public static ISet<string> GetOutputEntryNames(SignerConfig signerConfig, int minSdkVersion)
        {
            var result = new HashSet<string>();
            var signerName = signerConfig.Name;
            result.Add("META-INF/" + signerName + ".SF");
            var publicKey = signerConfig.Certificate.PublicKey;
            var signatureBlockFileName =
                "META-INF/" + signerName + ".";

            switch (publicKey.Key)
            {
                case RSACryptoServiceProvider _:
                    signatureBlockFileName += "RSA";
                    break;
                case DSACryptoServiceProvider _:
                    signatureBlockFileName += "DSA";
                    break;
            }

            result.Add(signatureBlockFileName);
            result.Add(ManifestEntryName);
            return result;
        }

        /// <summary>
        /// Returns <code>true</code> if the provided JAR entry must be mentioned in signed JAR archive's manifest.
        /// </summary>
        /// <param name="entryName"></param>
        /// <returns></returns>
        public static bool IsJarEntryDigestNeededInManifest(string entryName)
        {
            // See https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File
            // Entries which represent directories sould not be listed in the manifest.
            if (entryName.EndsWith("/"))
            {
                return false;
            }

            // Entries outside of META-INF must be listed in the manifest.
            if (!entryName.StartsWith("META-INF/"))
            {
                return true;
            }

            // Entries in subdirectories of META-INF must be listed in the manifest.
            if (entryName.IndexOf('/', "META-INF/".Length) != -1)
            {
                return true;
            }

            // Ignored file names (case-insensitive) in META-INF directory:
            //   MANIFEST.MF
            //   *.SF
            //   *.RSA
            //   *.DSA
            //   *.EC
            //   SIG-*
            var fileNameLowerCase =
                entryName.Substring("META-INF/".Length).ToLowerInvariant();
            if (("manifest.mf".Equals(fileNameLowerCase))
                || (fileNameLowerCase.EndsWith(".sf"))
                || (fileNameLowerCase.EndsWith(".rsa"))
                || (fileNameLowerCase.EndsWith(".dsa"))
                || (fileNameLowerCase.EndsWith(".ec"))
                || (fileNameLowerCase.StartsWith("sig-")))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Gets the JAR signing digest algorithm to be used for signing an APK using the provided key.
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="minSdkVersion">minimum API Level of the platform on which the APK may be installed (see AndroidManifest.xml minSdkVersion attribute)</param>
        /// <returns></returns>
        public static DigestAlgorithm GetSuggestedSignatureDigestAlgorithm(PublicKey certificate, int minSdkVersion)
        {
            switch (certificate.Key)
            {
                // Prior to API Level 18, only SHA-1 can be used with RSA.
                case RSA _ when minSdkVersion < 18:
                    return DigestAlgorithm.SHA1;
                case RSA _:
                    return DigestAlgorithm.SHA256;
                // Prior to API Level 21, only SHA-1 can be used with DSA
                case DSA _ when minSdkVersion < 21:
                    return DigestAlgorithm.SHA1;
                case DSA _:
                    return DigestAlgorithm.SHA256;
                case ECDsa _ when minSdkVersion < 18:
                    throw new CryptographicException(
                        "ECDSA signatures only supported for minSdkVersion 18 and higher");
                case ECDsa _:
                    return DigestAlgorithm.SHA256;
                default:
                    throw new CryptographicException("Unsupported key algorithm: " +
                                                     certificate.Key.GetType().FullName);
            }
        }

        /// <summary>
        /// Signs the provided APK using JAR signing (aka v1 signature scheme) and returns the list of
        /// JAR entries which need to be added to the APK as part of the signature.
        /// </summary>
        /// <param name="signerConfig"></param>
        /// <param name="jarEntryDigestAlgorithm"></param>
        /// <param name="jarEntryDigests"></param>
        /// <param name="apkSigningSchemeIds"></param>
        /// <param name="sourceManifestBytes"></param>
        /// <returns></returns>
        public static List<Tuple<string, byte[]>> Sign(SignerConfig signerConfig,
            DigestAlgorithm jarEntryDigestAlgorithm, IDictionary<string, byte[]> jarEntryDigests,
            IList<int> apkSigningSchemeIds, byte[] sourceManifestBytes)
        {
            var manifest =
                GenerateManifestFile(
                    jarEntryDigestAlgorithm, jarEntryDigests, sourceManifestBytes);
            return SignManifest(
                signerConfig, jarEntryDigestAlgorithm, apkSigningSchemeIds, manifest);
        }

        /// <summary>
        /// Generated and returns the <code>META-INF/MANIFEST.MF</code> file based on the provided (optional)
        /// input <code>MANIFEST.MF</code> and digests of JAR entries covered by the manifest.
        /// </summary>
        /// <param name="jarEntryDigestAlgorithm"></param>
        /// <param name="jarEntryDigests"></param>
        /// <param name="sourceManifestBytes"></param>
        /// <returns></returns>
        public static OutputManifestFile GenerateManifestFile(DigestAlgorithm jarEntryDigestAlgorithm,
            IDictionary<string, byte[]> jarEntryDigests, byte[] sourceManifestBytes)
        {
            Manifest.Manifest sourceManifest = null;
            if (sourceManifestBytes != null)
            {
                try
                {
                    sourceManifest = new Manifest.Manifest(sourceManifestBytes);
                }
                catch (IOException e)
                {
                    throw new ApkFormatException("Malformed source META-INF/MANIFEST.MF", e);
                }
            }

            var manifestOut = new MemoryStream();
            var mainAttrs = new Dictionary<string, string>();
            // Copy the main section from the source manifest (if provided). Otherwise use defaults.
            // NOTE: We don't output our own Created-By header because this signer did not create the
            //       JAR/APK being signed -- the signer only adds signatures to the already existing
            //       JAR/APK.
            if (sourceManifest != null)
            {
                foreach (var kvp in sourceManifest.MainAttributes)
                {
                    mainAttrs.Add(kvp.Key, kvp.Value);
                }
            }
            else
            {
                mainAttrs.Add(Manifest.Manifest.ManifestVersion, AttributeValueManifestVersion);
            }

            try
            {
                ManifestWriter.WriteMainSection(manifestOut, mainAttrs);
            }
            catch (IOException e)
            {
                throw new Exception("Failed to write in-memory MANIFEST.MF", e);
            }

            var sortedEntryNames = new List<string>(jarEntryDigests.Keys);
            sortedEntryNames.Sort(StringComparer.Ordinal);


            var invidualSectionsContents = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
            var entryDigestAttributeName = GetEntryDigestAttributeName(jarEntryDigestAlgorithm);
            foreach (var entryName in sortedEntryNames)
            {
                CheckEntryNameValid(entryName);
                var entryDigest = jarEntryDigests[entryName];
                var entryAttrs = new Dictionary<string, string>();
                entryAttrs.Add(
                    entryDigestAttributeName,
                    Convert.ToBase64String(entryDigest));
                var sectionOut = new MemoryStream();
                byte[] sectionBytes;
                try
                {
                    ManifestWriter.WriteIndividualSection(sectionOut, entryName, entryAttrs);
                    sectionBytes = sectionOut.ToArray();
                    manifestOut.Write(sectionBytes, 0, sectionBytes.Length);
                }
                catch (IOException e)
                {
                    throw new Exception("Failed to write in-memory MANIFEST.MF", e);
                }

                invidualSectionsContents.Add(entryName, sectionBytes);
            }

            var result = new OutputManifestFile
            {
                Contents = manifestOut.ToArray(),
                MainSectionAttributes = mainAttrs,
                IndividualSectionsContents = invidualSectionsContents
            };
            return result;
        }

        private static string GetEntryDigestAttributeName(DigestAlgorithm digestAlgorithm)
        {
            if (digestAlgorithm.Equals(DigestAlgorithm.SHA1))
            {
                return "SHA1-Digest";
            }

            if (digestAlgorithm.Equals(DigestAlgorithm.SHA256))
            {
                return "SHA-256-Digest";
            }

            throw new ArgumentException(
                "Unexpected content digest algorithm: " + digestAlgorithm);
        }


        private static void CheckEntryNameValid(string name)
        {
            // JAR signing spec says CR, LF, and NUL are not permitted in entry names
            // CR or LF in entry names will result in malformed MANIFEST.MF and .SF files because there
            // is no way to escape characters in MANIFEST.MF and .SF files. NUL can, presumably, cause
            // issues when parsing using C and C++ like languages.
            foreach (var c in name)
            {
                if ((c == '\r') || (c == '\n') || (c == 0))
                {
                    throw new ApkFormatException(
                        $"Unsupported character 0x{(int)c:X2} in ZIP entry name \"{name}\"");
                }
            }
        }


        public class OutputManifestFile
        {
            public byte[] Contents { get; set; }
            public SortedDictionary<string, byte[]> IndividualSectionsContents { get; set; }
            public Dictionary<string, string> MainSectionAttributes { get; set; }
        }


        /// <summary>
        /// Signs the provided APK using JAR signing (aka v1 signature scheme) and returns the list of
        /// JAR entries which need to be added to the APK as part of the signature.
        /// </summary>
        /// <param name="signerConfig"></param>
        /// <param name="digestAlgorithm"></param>
        /// <param name="apkSigningSchemeIds"></param>
        /// <param name="manifest"></param>
        /// <returns></returns>
        public static List<Tuple<string, byte[]>> SignManifest(SignerConfig signerConfig,
            DigestAlgorithm digestAlgorithm, IList<int> apkSigningSchemeIds, OutputManifestFile manifest)
        {
            // For each signer output .SF and .(RSA|DSA|EC) file, then output MANIFEST.MF.
            var signatureJarEntries =
                new List<Tuple<string, byte[]>>(2 * 1 + 1);
            var sfBytes = GenerateSignatureFile(apkSigningSchemeIds, digestAlgorithm, manifest);
            var signerName = signerConfig.Name;
            var signatureBlock = GenerateSignatureBlock(signerConfig, sfBytes);
            signatureJarEntries.Add(Tuple.Create("META-INF/" + signerName + ".SF", sfBytes));

            var publicKey = signerConfig.Certificate.PublicKey;
            var signatureBlockFileName =
                "META-INF/" + signerName + ".";

            if (publicKey.Key is RSACryptoServiceProvider)
            {
                signatureBlockFileName += "RSA";
            }
            else if (publicKey.Key is DSACryptoServiceProvider)
            {
                signatureBlockFileName += "DSA";
            }

            signatureJarEntries.Add(
                Tuple.Create(signatureBlockFileName, signatureBlock));
            signatureJarEntries.Add(Tuple.Create(ManifestEntryName, manifest.Contents));
            return signatureJarEntries;
        }

        private static byte[] GenerateSignatureFile(IList<int> apkSignatureSchemeIds,
            DigestAlgorithm manifestDigestAlgorithm, OutputManifestFile manifest)
        {
            var sf = new Manifest.Manifest();
            var mainAttrs = sf.MainAttributes;
            mainAttrs.Add(Manifest.Manifest.SignatureVersion, AttributeValueSignatureVersion);
            mainAttrs.Add(AttributeNameCreatedBy, "1.0 (Android)");
            //mainAttrs.Add(ATTRIBUTE_NAME_CREATED_BY, createdBy);
            if (apkSignatureSchemeIds.Any())
            {
                // Add APK Signature Scheme v2 (and newer) signature stripping protection.
                // This attribute indicates that this APK is supposed to have been signed using one or
                // more APK-specific signature schemes in addition to the standard JAR signature scheme
                // used by this code. APK signature verifier should reject the APK if it does not
                // contain a signature for the signature scheme the verifier prefers out of this set.
                var attrValue = new StringBuilder();
                foreach (var id in apkSignatureSchemeIds)
                {
                    if (attrValue.Length > 0)
                    {
                        attrValue.Append(", ");
                    }

                    attrValue.Append(id);
                }

                mainAttrs.Add(
                    SfAttributeNameAndroidApkSignedName,
                    attrValue.ToString());
            }

            // Add main attribute containing the digest of MANIFEST.MF.
            var md = GetMessageDigestInstance(manifestDigestAlgorithm);
            mainAttrs.Add(manifestDigestAlgorithm.DigestManifestAttributeName,
                Convert.ToBase64String(md.ComputeHash(manifest.Contents)));
            var @out = new MemoryStream();
            SignatureFileWriter.WriteMainSection(@out, mainAttrs);

            var entryDigestAttributeName = GetEntryDigestAttributeName(manifestDigestAlgorithm);
            foreach (var manifestSection in manifest.IndividualSectionsContents)
            {
                var sectionName = manifestSection.Key;
                var sectionContents = manifestSection.Value;
                var sectionDigest = md.ComputeHash(sectionContents);
                var attrs = new Dictionary<string, string>();
                attrs.Add(
                    entryDigestAttributeName,
                    Convert.ToBase64String(sectionDigest));
                SignatureFileWriter.WriteIndividualSection(@out, sectionName, attrs);
            }

            // A bug in the java.util.jar implementation of Android platforms up to version 1.6 will
            // cause a spurious IOException to be thrown if the length of the signature file is a
            // multiple of 1024 bytes. As a workaround, add an extra CRLF in this case.
            if ((@out.Length > 0) && ((@out.Length % 1024) == 0))
            {
                SignatureFileWriter.WriteSectionDelimiter(@out);
            }

            return @out.ToArray();
        }

        private static HashAlgorithm GetMessageDigestInstance(DigestAlgorithm manifestDigestAlgorithm)
        {
            return manifestDigestAlgorithm.CreateInstance();
        }


        private static byte[] GenerateSignatureBlock(SignerConfig signerConfig, byte[] signatureFileBytes)
        {
            var signerCert = signerConfig.Certificate;
            var digestAlgorithm = signerConfig.SignatureDigestAlgorithm;

            var digestAlgorithmId = digestAlgorithm.Oid;

            var content = new ContentInfo(DataOid, signatureFileBytes);
            var signedCms = new SignedCms(content, true);

            var signer = new CmsSigner(signerCert)
            {
                DigestAlgorithm = digestAlgorithmId
            };
            signedCms.ComputeSignature(signer);

            var encoded = signedCms.Encode();
            return encoded;
        }

        public static string GetSafeSignerName(string name)
        {
            // According to https://docs.oracle.com/javase/tutorial/deployment/jar/signing.html, the
            // name must not be longer than 8 characters and may contain only A-Z, 0-9, _, and -.
            var result = new StringBuilder();
            var nameCharsUpperCase = name.ToUpperInvariant().ToCharArray();
            for (var i = 0; i < Math.Min(nameCharsUpperCase.Length, 8); i++)
            {
                var c = nameCharsUpperCase[i];
                if (((c >= 'A') && (c <= 'Z'))
                    || ((c >= '0') && (c <= '9'))
                    || (c == '-')
                    || (c == '_'))
                {
                    result.Append(c);
                }
                else
                {
                    result.Append('_');
                }
            }

            return result.ToString();
        }
    }
}