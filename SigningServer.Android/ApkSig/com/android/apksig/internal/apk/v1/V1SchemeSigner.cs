// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1
{
    /// <summary>
    /// APK signer which uses JAR signing (aka v1 signing scheme).
    /// 
    /// @see &lt;a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File"&gt;Signed JAR File&lt;/a&gt;
    /// </summary>
    public abstract class V1SchemeSigner
    {
        public static readonly string MANIFEST_ENTRY_NAME = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeConstants.MANIFEST_ENTRY_NAME;
        
        internal static readonly SigningServer.Android.Util.Jar.Attributes.Name ATTRIBUTE_NAME_CREATED_BY = new SigningServer.Android.Util.Jar.Attributes.Name("Created-By");
        
        internal static readonly string ATTRIBUTE_VALUE_MANIFEST_VERSION = "1.0";
        
        internal static readonly string ATTRIBUTE_VALUE_SIGNATURE_VERSION = "1.0";
        
        internal static readonly SigningServer.Android.Util.Jar.Attributes.Name SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME = new SigningServer.Android.Util.Jar.Attributes.Name(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeConstants.SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME_STR);
        
        /// <summary>
        /// Signer configuration.
        /// </summary>
        public class SignerConfig
        {
            /// <summary>
            /// Name.
            /// </summary>
            public string name;
            
            /// <summary>
            /// Private key.
            /// </summary>
            public SigningServer.Android.Security.PrivateKey privateKey;
            
            /// <summary>
            /// Certificates, with the first certificate containing the public key corresponding to
            /// {@link #privateKey}.
            /// </summary>
            public SigningServer.Android.Collections.List<SigningServer.Android.Security.Cert.X509Certificate> certificates;
            
            /// <summary>
            /// Digest algorithm used for the signature.
            /// </summary>
            public SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm signatureDigestAlgorithm;
            
            /// <summary>
            /// If DSA is the signing algorithm, whether or not deterministic DSA signing should be used.
            /// </summary>
            public bool deterministicDsaSigning;
            
        }
        
        /// <summary>
        /// Hidden constructor to prevent instantiation.
        /// </summary>
        internal V1SchemeSigner()
        {
        }
        
        /// <summary>
        /// Gets the JAR signing digest algorithm to be used for signing an APK using the provided key.
        /// 
        /// @param minSdkVersion minimum API Level of the platform on which the APK may be installed (see
        ///        AndroidManifest.xml minSdkVersion attribute)
        /// @throws InvalidKeyException if the provided key is not suitable for signing APKs using
        ///         JAR signing (aka v1 signature scheme)
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm GetSuggestedSignatureDigestAlgorithm(SigningServer.Android.Security.PublicKey signingKey, int minSdkVersion)
        {
            string keyAlgorithm = signingKey.GetAlgorithm();
            if ("RSA".EqualsIgnoreCase(keyAlgorithm))
            {
                if (minSdkVersion < 18)
                {
                    return SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA1;
                }
                return SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA256;
            }
            else if ("DSA".EqualsIgnoreCase(keyAlgorithm))
            {
                if (minSdkVersion < 21)
                {
                    return SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA1;
                }
                else 
                {
                    return SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA256;
                }
            }
            else if ("EC".EqualsIgnoreCase(keyAlgorithm))
            {
                if (minSdkVersion < 18)
                {
                    throw new SigningServer.Android.Security.InvalidKeyException("ECDSA signatures only supported for minSdkVersion 18 and higher");
                }
                return SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA256;
            }
            else 
            {
                throw new SigningServer.Android.Security.InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
            }
        }
        
        /// <summary>
        /// Returns a safe version of the provided signer name.
        /// </summary>
        public static string GetSafeSignerName(string name)
        {
            if (name.IsEmpty())
            {
                throw new System.ArgumentException("Empty name");
            }
            SigningServer.Android.Core.StringBuilder result = new SigningServer.Android.Core.StringBuilder();
            char[] nameCharsUpperCase = name.ToUpperCase(SigningServer.Android.Util.Locale.US).ToCharArray();
            for (int i = 0;i < SigningServer.Android.Core.Math.Min(nameCharsUpperCase.Length, 8);i++)
            {
                char c = nameCharsUpperCase[i];
                if (((c >= 'A') && (c <= 'Z')) || ((c >= '0') && (c <= '9')) || (c == '-') || (c == '_'))
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
        
        /// <summary>
        /// Returns a new {@link MessageDigest} instance corresponding to the provided digest algorithm.
        /// </summary>
        internal static SigningServer.Android.Security.MessageDigest GetMessageDigestInstance(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm digestAlgorithm)
        {
            string jcaAlgorithm = digestAlgorithm.GetJcaMessageDigestAlgorithm();
            return SigningServer.Android.Security.MessageDigest.GetInstance(jcaAlgorithm);
        }
        
        /// <summary>
        /// Returns the JCA {@link MessageDigest} algorithm corresponding to the provided digest
        /// algorithm.
        /// </summary>
        public static string GetJcaMessageDigestAlgorithm(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm digestAlgorithm)
        {
            return digestAlgorithm.GetJcaMessageDigestAlgorithm();
        }
        
        /// <summary>
        /// Returns {@code true} if the provided JAR entry must be mentioned in signed JAR archive's
        /// manifest.
        /// </summary>
        public static bool IsJarEntryDigestNeededInManifest(string entryName)
        {
            if (entryName.EndsWith("/"))
            {
                return false;
            }
            if (!entryName.StartsWith("META-INF/"))
            {
                return true;
            }
            if (entryName.IndexOf('/', "META-INF/".Length()) != -1)
            {
                return true;
            }
            string fileNameLowerCase = entryName.SubstringIndex("META-INF/".Length()).ToLowerCase(SigningServer.Android.Util.Locale.US);
            if (("manifest.mf".Equals(fileNameLowerCase)) || (fileNameLowerCase.EndsWith(".sf")) || (fileNameLowerCase.EndsWith(".rsa")) || (fileNameLowerCase.EndsWith(".dsa")) || (fileNameLowerCase.EndsWith(".ec")) || (fileNameLowerCase.StartsWith("sig-")))
            {
                return false;
            }
            return true;
        }
        
        /// <summary>
        /// Signs the provided APK using JAR signing (aka v1 signature scheme) and returns the list of
        /// JAR entries which need to be added to the APK as part of the signature.
        /// 
        /// @param signerConfigs signer configurations, one for each signer. At least one signer config
        ///        must be provided.
        /// @throws ApkFormatException if the source manifest is malformed
        /// @throws NoSuchAlgorithmException if a required cryptographic algorithm implementation is
        ///         missing
        /// @throws InvalidKeyException if a signing key is not suitable for this signature scheme or
        ///         cannot be used in general
        /// @throws SignatureException if an error occurs when computing digests of generating
        ///         signatures
        /// </summary>
        public static SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<string, sbyte[]>> Sign(SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.SignerConfig> signerConfigs, SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm jarEntryDigestAlgorithm, SigningServer.Android.Collections.Map<string, sbyte[]> jarEntryDigests, SigningServer.Android.Collections.List<int?> apkSigningSchemeIds, sbyte[] sourceManifestBytes, string createdBy)
        {
            if (signerConfigs.IsEmpty())
            {
                throw new System.ArgumentException("At least one signer config must be provided");
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.OutputManifestFile manifest = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.GenerateManifestFile(jarEntryDigestAlgorithm, jarEntryDigests, sourceManifestBytes);
            return SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.SignManifest(signerConfigs, jarEntryDigestAlgorithm, apkSigningSchemeIds, createdBy, manifest);
        }
        
        /// <summary>
        /// Signs the provided APK using JAR signing (aka v1 signature scheme) and returns the list of
        /// JAR entries which need to be added to the APK as part of the signature.
        /// 
        /// @param signerConfigs signer configurations, one for each signer. At least one signer config
        ///        must be provided.
        /// @throws InvalidKeyException if a signing key is not suitable for this signature scheme or
        ///         cannot be used in general
        /// @throws SignatureException if an error occurs when computing digests of generating
        ///         signatures
        /// </summary>
        public static SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<string, sbyte[]>> SignManifest(SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.SignerConfig> signerConfigs, SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm digestAlgorithm, SigningServer.Android.Collections.List<int?> apkSigningSchemeIds, string createdBy, SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.OutputManifestFile manifest)
        {
            if (signerConfigs.IsEmpty())
            {
                throw new System.ArgumentException("At least one signer config must be provided");
            }
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<string, sbyte[]>> signatureJarEntries = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<string, sbyte[]>>(2 * signerConfigs.Size() + 1);
            sbyte[] sfBytes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.GenerateSignatureFile(apkSigningSchemeIds, digestAlgorithm, createdBy, manifest);
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.SignerConfig signerConfig in signerConfigs)
            {
                string signerName = signerConfig.name;
                sbyte[] signatureBlock;
                try
                {
                    signatureBlock = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.GenerateSignatureBlock(signerConfig, sfBytes);
                }
                catch (SigningServer.Android.Security.InvalidKeyException e)
                {
                    throw new SigningServer.Android.Security.InvalidKeyException("Failed to sign using signer \\" + signerName + "\\", e);
                }
                catch (SigningServer.Android.Security.Cert.CertificateException e)
                {
                    throw new SigningServer.Android.Security.Cert.CertificateException("Failed to sign using signer \\" + signerName + "\\", e);
                }
                catch (SigningServer.Android.Security.SignatureException e)
                {
                    throw new SigningServer.Android.Security.SignatureException("Failed to sign using signer \\" + signerName + "\\", e);
                }
                signatureJarEntries.Add(SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, sbyte[]>("META-INF/" + signerName + ".SF", sfBytes));
                SigningServer.Android.Security.PublicKey publicKey = signerConfig.certificates.Get(0).GetPublicKey();
                string signatureBlockFileName = "META-INF/" + signerName + "." + publicKey.GetAlgorithm().ToUpperCase(SigningServer.Android.Util.Locale.US);
                signatureJarEntries.Add(SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, sbyte[]>(signatureBlockFileName, signatureBlock));
            }
            signatureJarEntries.Add(SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, sbyte[]>(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeConstants.MANIFEST_ENTRY_NAME, manifest.contents));
            return signatureJarEntries;
        }
        
        /// <summary>
        /// Returns the names of JAR entries which this signer will produce as part of v1 signature.
        /// </summary>
        public static SigningServer.Android.Collections.Set<string> GetOutputEntryNames(SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.SignerConfig> signerConfigs)
        {
            SigningServer.Android.Collections.Set<string> result = new SigningServer.Android.Collections.HashSet<string>(2 * signerConfigs.Size() + 1);
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.SignerConfig signerConfig in signerConfigs)
            {
                string signerName = signerConfig.name;
                result.Add("META-INF/" + signerName + ".SF");
                SigningServer.Android.Security.PublicKey publicKey = signerConfig.certificates.Get(0).GetPublicKey();
                string signatureBlockFileName = "META-INF/" + signerName + "." + publicKey.GetAlgorithm().ToUpperCase(SigningServer.Android.Util.Locale.US);
                result.Add(signatureBlockFileName);
            }
            result.Add(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeConstants.MANIFEST_ENTRY_NAME);
            return result;
        }
        
        /// <summary>
        /// Generated and returns the {@code META-INF/MANIFEST.MF} file based on the provided (optional)
        /// input {@code MANIFEST.MF} and digests of JAR entries covered by the manifest.
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.OutputManifestFile GenerateManifestFile(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm jarEntryDigestAlgorithm, SigningServer.Android.Collections.Map<string, sbyte[]> jarEntryDigests, sbyte[] sourceManifestBytes)
        {
            SigningServer.Android.Util.Jar.Manifest sourceManifest = null;
            if (sourceManifestBytes != null)
            {
                try
                {
                    sourceManifest = new SigningServer.Android.Util.Jar.Manifest(new SigningServer.Android.IO.ByteArrayInputStream(sourceManifestBytes));
                }
                catch (global::System.IO.IOException e)
                {
                    throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Malformed source META-INF/MANIFEST.MF", e);
                }
            }
            SigningServer.Android.IO.ByteArrayOutputStream manifestOut = new SigningServer.Android.IO.ByteArrayOutputStream();
            SigningServer.Android.Util.Jar.Attributes mainAttrs = new SigningServer.Android.Util.Jar.Attributes();
            if (sourceManifest != null)
            {
                mainAttrs.PutAll(sourceManifest.GetMainAttributes());
            }
            else 
            {
                mainAttrs.Put(SigningServer.Android.Util.Jar.Attributes.Name.MANIFEST_VERSION, SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.ATTRIBUTE_VALUE_MANIFEST_VERSION);
            }
            try
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteMainSection(manifestOut, mainAttrs);
            }
            catch (global::System.IO.IOException e)
            {
                throw new SigningServer.Android.Core.RuntimeException("Failed to write in-memory MANIFEST.MF", e);
            }
            SigningServer.Android.Collections.List<string> sortedEntryNames = new SigningServer.Android.Collections.List<string>(jarEntryDigests.KeySet());
            SigningServer.Android.Util.Collections.Sort(sortedEntryNames);
            SigningServer.Android.Collections.SortedMap<string, sbyte[]> invidualSectionsContents = new SigningServer.Android.Collections.TreeMap<string, sbyte[]>();
            string entryDigestAttributeName = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.GetEntryDigestAttributeName(jarEntryDigestAlgorithm);
            foreach (string entryName in sortedEntryNames)
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.CheckEntryNameValid(entryName);
                sbyte[] entryDigest = jarEntryDigests.Get(entryName);
                SigningServer.Android.Util.Jar.Attributes entryAttrs = new SigningServer.Android.Util.Jar.Attributes();
                entryAttrs.PutValue(entryDigestAttributeName, SigningServer.Android.Util.Base64.GetEncoder().EncodeToString(entryDigest));
                SigningServer.Android.IO.ByteArrayOutputStream sectionOut = new SigningServer.Android.IO.ByteArrayOutputStream();
                sbyte[] sectionBytes;
                try
                {
                    SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteIndividualSection(sectionOut, entryName, entryAttrs);
                    sectionBytes = sectionOut.ToByteArray();
                    manifestOut.Write(sectionBytes);
                }
                catch (global::System.IO.IOException e)
                {
                    throw new SigningServer.Android.Core.RuntimeException("Failed to write in-memory MANIFEST.MF", e);
                }
                invidualSectionsContents.Put(entryName, sectionBytes);
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.OutputManifestFile result = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.OutputManifestFile();
            result.contents = manifestOut.ToByteArray();
            result.mainSectionAttributes = mainAttrs;
            result.individualSectionsContents = invidualSectionsContents;
            return result;
        }
        
        internal static void CheckEntryNameValid(string name)
        {
            foreach (char c in name.ToCharArray())
            {
                if ((c == '\r') || (c == '\n') || (c == 0))
                {
                    throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException(SigningServer.Android.Core.StringExtensions.Format("Unsupported character 0x%1$02x in ZIP entry name \\%2$s\\", (int)c, name));
                }
            }
        }
        
        public class OutputManifestFile
        {
            public sbyte[] contents;
            
            public SigningServer.Android.Collections.SortedMap<string, sbyte[]> individualSectionsContents;
            
            public SigningServer.Android.Util.Jar.Attributes mainSectionAttributes;
            
        }
        
        internal static sbyte[] GenerateSignatureFile(SigningServer.Android.Collections.List<int?> apkSignatureSchemeIds, SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm manifestDigestAlgorithm, string createdBy, SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.OutputManifestFile manifest)
        {
            SigningServer.Android.Util.Jar.Manifest sf = new SigningServer.Android.Util.Jar.Manifest();
            SigningServer.Android.Util.Jar.Attributes mainAttrs = sf.GetMainAttributes();
            mainAttrs.Put(SigningServer.Android.Util.Jar.Attributes.Name.SIGNATURE_VERSION, SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.ATTRIBUTE_VALUE_SIGNATURE_VERSION);
            mainAttrs.Put(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.ATTRIBUTE_NAME_CREATED_BY, createdBy);
            if (!apkSignatureSchemeIds.IsEmpty())
            {
                SigningServer.Android.Core.StringBuilder attrValue = new SigningServer.Android.Core.StringBuilder();
                foreach (int id in apkSignatureSchemeIds)
                {
                    if (attrValue.Length() > 0)
                    {
                        attrValue.Append(", ");
                    }
                    attrValue.Append(SigningServer.Android.Core.StringExtensions.ValueOf(id));
                }
                mainAttrs.Put(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME, attrValue.ToString());
            }
            SigningServer.Android.Security.MessageDigest md = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.GetMessageDigestInstance(manifestDigestAlgorithm);
            mainAttrs.PutValue(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.GetManifestDigestAttributeName(manifestDigestAlgorithm), SigningServer.Android.Util.Base64.GetEncoder().EncodeToString(md.Digest(manifest.contents)));
            SigningServer.Android.IO.ByteArrayOutputStream output = new SigningServer.Android.IO.ByteArrayOutputStream();
            try
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Jar.SignatureFileWriter.WriteMainSection(output, mainAttrs);
            }
            catch (global::System.IO.IOException e)
            {
                throw new SigningServer.Android.Core.RuntimeException("Failed to write in-memory .SF file", e);
            }
            string entryDigestAttributeName = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.GetEntryDigestAttributeName(manifestDigestAlgorithm);
            foreach (SigningServer.Android.Collections.MapEntry<string, sbyte[]> manifestSection in manifest.individualSectionsContents.EntrySet())
            {
                string sectionName = manifestSection.GetKey();
                sbyte[] sectionContents = manifestSection.GetValue();
                sbyte[] sectionDigest = md.Digest(sectionContents);
                SigningServer.Android.Util.Jar.Attributes attrs = new SigningServer.Android.Util.Jar.Attributes();
                attrs.PutValue(entryDigestAttributeName, SigningServer.Android.Util.Base64.GetEncoder().EncodeToString(sectionDigest));
                try
                {
                    SigningServer.Android.Com.Android.Apksig.Internal.Jar.SignatureFileWriter.WriteIndividualSection(output, sectionName, attrs);
                }
                catch (global::System.IO.IOException e)
                {
                    throw new SigningServer.Android.Core.RuntimeException("Failed to write in-memory .SF file", e);
                }
            }
            if ((output.Size() > 0) && ((output.Size() % 1024) == 0))
            {
                try
                {
                    SigningServer.Android.Com.Android.Apksig.Internal.Jar.SignatureFileWriter.WriteSectionDelimiter(output);
                }
                catch (global::System.IO.IOException e)
                {
                    throw new SigningServer.Android.Core.RuntimeException("Failed to write to ByteArrayOutputStream", e);
                }
            }
            return output.ToByteArray();
        }
        
        /// <summary>
        /// Generates the CMS PKCS #7 signature block corresponding to the provided signature file and
        /// signing configuration.
        /// </summary>
        internal static sbyte[] GenerateSignatureBlock(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeSigner.SignerConfig signerConfig, sbyte[] signatureFileBytes)
        {
            SigningServer.Android.Collections.List<SigningServer.Android.Security.Cert.X509Certificate> signerCerts = signerConfig.certificates;
            SigningServer.Android.Security.Cert.X509Certificate signingCert = signerCerts.Get(0);
            SigningServer.Android.Security.PublicKey publicKey = signingCert.GetPublicKey();
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm digestAlgorithm = signerConfig.signatureDigestAlgorithm;
            SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<string, SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier> signatureAlgs = SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier.GetSignerInfoSignatureAlgorithm(publicKey, digestAlgorithm, signerConfig.deterministicDsaSigning);
            string jcaSignatureAlgorithm = signatureAlgs.GetFirst();
            sbyte[] signatureBytes;
            try
            {
                SigningServer.Android.Security.Signature signature = SigningServer.Android.Security.Signature.GetInstance(jcaSignatureAlgorithm);
                signature.InitSign(signerConfig.privateKey);
                signature.Update(signatureFileBytes);
                signatureBytes = signature.Sign();
            }
            catch (SigningServer.Android.Security.InvalidKeyException e)
            {
                throw new SigningServer.Android.Security.InvalidKeyException("Failed to sign using " + jcaSignatureAlgorithm, e);
            }
            catch (SigningServer.Android.Security.SignatureException e)
            {
                throw new SigningServer.Android.Security.SignatureException("Failed to sign using " + jcaSignatureAlgorithm, e);
            }
            try
            {
                SigningServer.Android.Security.Signature signature = SigningServer.Android.Security.Signature.GetInstance(jcaSignatureAlgorithm);
                signature.InitVerify(publicKey);
                signature.Update(signatureFileBytes);
                if (!signature.Verify(signatureBytes))
                {
                    throw new SigningServer.Android.Security.SignatureException("Signature did not verify");
                }
            }
            catch (SigningServer.Android.Security.InvalidKeyException e)
            {
                throw new SigningServer.Android.Security.InvalidKeyException("Failed to verify generated " + jcaSignatureAlgorithm + " signature using" + " public key from certificate", e);
            }
            catch (SigningServer.Android.Security.SignatureException e)
            {
                throw new SigningServer.Android.Security.SignatureException("Failed to verify generated " + jcaSignatureAlgorithm + " signature using" + " public key from certificate", e);
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier digestAlgorithmId = SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier.GetSignerInfoDigestAlgorithmOid(digestAlgorithm);
            SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier signatureAlgorithmId = signatureAlgs.GetSecond();
            try
            {
                return SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GeneratePkcs7DerEncodedMessage(signatureBytes, null, signerCerts, digestAlgorithmId, signatureAlgorithmId);
            }
            catch (System.Exception ex) when ( ex is SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1EncodingException || ex is SigningServer.Android.Security.Cert.CertificateEncodingException)
            {
                throw new SigningServer.Android.Security.SignatureException("Failed to encode signature block");
            }
        }
        
        internal static string GetEntryDigestAttributeName(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm digestAlgorithm)
        {
            switch (digestAlgorithm.Case)
            {
                case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA1_CASE:
                    return "SHA1-Digest";
                case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA256_CASE:
                    return "SHA-256-Digest";
                default:
                    throw new System.ArgumentException("Unexpected content digest algorithm: " + digestAlgorithm);
            }
        }
        
        internal static string GetManifestDigestAttributeName(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm digestAlgorithm)
        {
            switch (digestAlgorithm.Case)
            {
                case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA1_CASE:
                    return "SHA1-Digest-Manifest";
                case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA256_CASE:
                    return "SHA-256-Digest-Manifest";
                default:
                    throw new System.ArgumentException("Unexpected content digest algorithm: " + digestAlgorithm);
            }
        }
        
    }
    
}
