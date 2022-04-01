/*
 * Copyright (C) 2016 The Android Open Source Project
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
using System.Security.Cryptography;
using System.Text;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.ApkSig.Internal.Jar;
using SigningServer.Android.ApkSig.Internal.Pkcs7;

namespace SigningServer.Android.ApkSig.Internal.Apk.v1
{
    /**
 * APK signer which uses JAR signing (aka v1 signing scheme).
 *
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File">Signed JAR File</a>
 */
    public abstract class V1SchemeSigner
    {
        public static readonly String MANIFEST_ENTRY_NAME = V1SchemeConstants.MANIFEST_ENTRY_NAME;

        private static readonly Attributes.Name ATTRIBUTE_NAME_CREATED_BY =
            new Attributes.Name("Created-By");

        private static readonly String ATTRIBUTE_VALUE_MANIFEST_VERSION = "1.0";
        private static readonly String ATTRIBUTE_VALUE_SIGNATURE_VERSION = "1.0";

        private static readonly Attributes.Name SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME =
            new Attributes.Name(V1SchemeConstants.SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME_STR);

        /**
     * Signer configuration.
     */
        public class SignerConfig
        {
            /** Name. */
            public String name;

            /** Private key. */
            public PrivateKey privateKey;

            /**
         * Certificates, with the first certificate containing the public key corresponding to
         * {@link #privateKey}.
         */
            public List<X509Certificate> certificates;

            /**
         * Digest algorithm used for the signature.
         */
            public DigestAlgorithm signatureDigestAlgorithm;

            /**
         * If DSA is the signing algorithm, whether or not deterministic DSA signing should be used.
         */
            public bool deterministicDsaSigning;
        }

        /** Hidden constructor to prevent instantiation. */
        private V1SchemeSigner()
        {
        }

        /**
     * Gets the JAR signing digest algorithm to be used for signing an APK using the provided key.
     *
     * @param minSdkVersion minimum API Level of the platform on which the APK may be installed (see
     *        AndroidManifest.xml minSdkVersion attribute)
     *
     * @throws CryptographicException if the provided key is not suitable for signing APKs using
     *         JAR signing (aka v1 signature scheme)
     */
        public static DigestAlgorithm getSuggestedSignatureDigestAlgorithm(
            PublicKey signingKey, int minSdkVersion)
        {
            String keyAlgorithm = signingKey.getAlgorithm();
            if ("RSA".Equals(keyAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                // Prior to API Level 18, only SHA-1 can be used with RSA.
                if (minSdkVersion < 18)
                {
                    return DigestAlgorithm.SHA1;
                }

                return DigestAlgorithm.SHA256;
            }

            else if ("DSA".Equals(keyAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                // Prior to API Level 21, only SHA-1 can be used with DSA
                if (minSdkVersion < 21)
                {
                    return DigestAlgorithm.SHA1;
                }
                else
                {
                    return DigestAlgorithm.SHA256;
                }
            }
            else if ("EC".Equals(keyAlgorithm, StringComparison.Ordinal))
            {
                if (minSdkVersion < 18)
                {
                    throw new CryptographicException(
                        "ECDSA signatures only supported for minSdkVersion 18 and higher");
                }

                return DigestAlgorithm.SHA256;
            }
            else
            {
                throw new CryptographicException("Unsupported key algorithm: " + keyAlgorithm);
            }
        }

        /**
         * Returns a safe version of the provided signer name.
         */
        public static String getSafeSignerName(String name)
        {
            if (name.Length == 0)
            {
                throw new ArgumentException("Empty name");
            }

            // According to https://docs.oracle.com/javase/tutorial/deployment/jar/signing.html, the
            // name must not be longer than 8 characters and may contain only A-Z, 0-9, _, and -.
            StringBuilder result = new StringBuilder();
            char[] nameCharsUpperCase = name.ToUpperInvariant().ToCharArray();
            for (int i = 0; i < Math.Min(nameCharsUpperCase.Length, 8); i++)
            {
                char c = nameCharsUpperCase[i];
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

        /**
 * Returns a new {@link MessageDigest} instance corresponding to the provided digest algorithm.
 */
        private static HashAlgorithm getMessageDigestInstance(DigestAlgorithm digestAlgorithm)
        {
            String jcaAlgorithm = digestAlgorithm.getJcaMessageDigestAlgorithm();
            return HashAlgorithm.Create(jcaAlgorithm);
        }

        /**
 * Returns the JCA {@link MessageDigest} algorithm corresponding to the provided digest
 * algorithm.
 */
        public static String getJcaMessageDigestAlgorithm(DigestAlgorithm digestAlgorithm)
        {
            return digestAlgorithm.getJcaMessageDigestAlgorithm();
        }

        /**
 * Returns {@code true} if the provided JAR entry must be mentioned in signed JAR archive's
 * manifest.
 */
        public static bool isJarEntryDigestNeededInManifest(String entryName)
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
            String fileNameLowerCase =
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

        /**
 * Signs the provided APK using JAR signing (aka v1 signature scheme) and returns the list of
 * JAR entries which need to be added to the APK as part of the signature.
 *
 * @param signerConfigs signer configurations, one for each signer. At least one signer config
 *        must be provided.
 *
 * @throws ApkFormatException if the source manifest is malformed
 * @throws NoSuchAlgorithmException if a required cryptographic algorithm implementation is
 *         missing
 * @throws CryptographicException if a signing key is not suitable for this signature scheme or
 *         cannot be used in general
 * @throws SignatureException if an error occurs when computing digests of generating
 *         signatures
 */
        public static List<Tuple<String, byte[]>> sign(
            List<SignerConfig> signerConfigs,
            DigestAlgorithm jarEntryDigestAlgorithm,
            Dictionary<String, byte[]> jarEntryDigests,
            List<int> apkSigningSchemeIds,
            byte[] sourceManifestBytes,
            String createdBy)

        {
            if (signerConfigs.Count == 0)
            {
                throw new ArgumentException("At least one signer config must be provided");
            }

            OutputManifestFile manifest =
                generateManifestFile(
                    jarEntryDigestAlgorithm, jarEntryDigests, sourceManifestBytes);

            return signManifest(
                signerConfigs, jarEntryDigestAlgorithm, apkSigningSchemeIds, createdBy, manifest);
        }

        /**
 * Signs the provided APK using JAR signing (aka v1 signature scheme) and returns the list of
 * JAR entries which need to be added to the APK as part of the signature.
 *
 * @param signerConfigs signer configurations, one for each signer. At least one signer config
 *        must be provided.
 *
 * @throws CryptographicException if a signing key is not suitable for this signature scheme or
 *         cannot be used in general
 * @throws SignatureException if an error occurs when computing digests of generating
 *         signatures
 */
        public static List<Tuple<String, byte[]>> signManifest(
            List<SignerConfig> signerConfigs,
            DigestAlgorithm digestAlgorithm,
            List<int> apkSigningSchemeIds,
            String createdBy,
            OutputManifestFile manifest)

        {
            if (signerConfigs.Count == 0)
            {
                throw new ArgumentException("At least one signer config must be provided");
            }

            // For each signer output .SF and .(RSA|DSA|EC) file, then output MANIFEST.MF.
            List<Tuple<String, byte[]>> signatureJarEntries =
                new List<Tuple<String, byte[]>>(2 * signerConfigs.Count + 1);
            byte[] sfBytes =
                generateSignatureFile(apkSigningSchemeIds, digestAlgorithm, createdBy, manifest);
            foreach (SignerConfig signerConfig in signerConfigs)
            {
                String signerName = signerConfig.name;
                byte[] signatureBlock;
                try
                {
                    signatureBlock = generateSignatureBlock(signerConfig, sfBytes);
                }
                catch (CryptographicException e)
                {
                    throw new CryptographicException(
                        "Failed to sign using signer \"" + signerName + "\"", e);
                }

                signatureJarEntries.Add(Tuple.Create("META-INF/" + signerName + ".SF", sfBytes));
                PublicKey publicKey = signerConfig.certificates[0].getPublicKey();
                String signatureBlockFileName =
                    "META-INF/" + signerName + "."
                    + publicKey.getAlgorithm().ToUpperInvariant();
                signatureJarEntries.Add(
                    Tuple.Create(signatureBlockFileName, signatureBlock));
            }

            signatureJarEntries.Add(Tuple.Create(V1SchemeConstants.MANIFEST_ENTRY_NAME, manifest.contents));
            return signatureJarEntries;
        }

        /**
 * Returns the names of JAR entries which this signer will produce as part of v1 signature.
 */
        public static ISet<String> getOutputEntryNames(List<SignerConfig> signerConfigs)
        {
            ISet<String> result = new HashSet<string>(2 * signerConfigs.Count + 1);
            foreach (SignerConfig signerConfig in signerConfigs)
            {
                String signerName = signerConfig.name;
                result.Add("META-INF/" + signerName + ".SF");
                PublicKey publicKey = signerConfig.certificates[0].getPublicKey();
                String signatureBlockFileName =
                    "META-INF/" + signerName + "."
                    + publicKey.getAlgorithm().ToUpperInvariant();
                result.Add(signatureBlockFileName);
            }

            result.Add(V1SchemeConstants.MANIFEST_ENTRY_NAME);
            return result;
        }

        /**
 * Generated and returns the {@code META-INF/MANIFEST.MF} file based on the provided (optional)
 * input {@code MANIFEST.MF} and digests of JAR entries covered by the manifest.
 */
        public static OutputManifestFile generateManifestFile(
            DigestAlgorithm jarEntryDigestAlgorithm,
            Dictionary<String, byte[]> jarEntryDigests,
            byte[] sourceManifestBytes)

        {
            Manifest sourceManifest = null;
            if (sourceManifestBytes != null)
            {
                try
                {
                    sourceManifest = new Manifest(new MemoryStream(sourceManifestBytes));
                }
                catch (IOException e)
                {
                    throw new ApkFormatException("Malformed source META-INF/MANIFEST.MF", e);
                }
            }

            var manifestOut = new MemoryStream();
            Attributes mainAttrs = new Attributes();
            // Copy the main section from the source manifest (if provided). Otherwise use defaults.
            // NOTE: We don't output our own Created-By header because this signer did not create the
            //       JAR/APK being signed -- the signer only adds signatures to the already existing
            //       JAR/APK.
            if (sourceManifest != null)
            {
                foreach (var kvp in sourceManifest.getMainAttributes())
                {
                    mainAttrs[kvp.Key] = kvp.Value;
                }
            }
            else
            {
                mainAttrs[Attributes.Name.MANIFEST_VERSION.ToString()] = ATTRIBUTE_VALUE_MANIFEST_VERSION;
            }

            try
            {
                ManifestWriter.writeMainSection(manifestOut, mainAttrs);
            }
            catch (IOException e)
            {
                throw new ApplicationException("Failed to write in-memory MANIFEST.MF", e);
            }

            List<String> sortedEntryNames = new List<String>(jarEntryDigests.Keys);
            sortedEntryNames.Sort();
            SortedDictionary<String, byte[]> invidualSectionsContents = new SortedDictionary<string, byte[]>();
            String entryDigestAttributeName = getEntryDigestAttributeName(jarEntryDigestAlgorithm);
            foreach (String entryName in sortedEntryNames)
            {
                checkEntryNameValid(entryName);
                jarEntryDigests.TryGetValue(entryName, out var entryDigest);
                Attributes entryAttrs = new Attributes();
                entryAttrs.putValue(
                    entryDigestAttributeName,
                    Convert.ToBase64String(entryDigest));
                var sectionOut = new MemoryStream();
                byte[] sectionBytes;
                try
                {
                    ManifestWriter.writeIndividualSection(sectionOut, entryName, entryAttrs);
                    sectionBytes = sectionOut.ToArray();
                    manifestOut.Write(sectionBytes, 0, sectionBytes.Length);
                }
                catch (IOException e)
                {
                    throw new ApplicationException("Failed to write in-memory MANIFEST.MF", e);
                }

                invidualSectionsContents[entryName] = sectionBytes;
            }

            OutputManifestFile result = new OutputManifestFile();
            result.contents = manifestOut.ToArray();
            result.mainSectionAttributes = mainAttrs;
            result.individualSectionsContents = invidualSectionsContents;
            return result;
        }

        private static void checkEntryNameValid(String name)
        {
            // JAR signing spec says CR, LF, and NUL are not permitted in entry names
            // CR or LF in entry names will result in malformed MANIFEST.MF and .SF files because there
            // is no way to escape characters in MANIFEST.MF and .SF files. NUL can, presumably, cause
            // issues when parsing using C and C++ like languages.
            foreach (char c in name)
            {
                if ((c == '\r') || (c == '\n') || (c == 0))
                {
                    throw new ApkFormatException(
                        String.Format(
                            "Unsupported character 0x{0:X} in ZIP entry name \"{1}\"",
                            (int)c,
                            name));
                }
            }
        }

        public class OutputManifestFile
        {
            public byte[] contents;
            public SortedDictionary<String, byte[]> individualSectionsContents;
            public Attributes mainSectionAttributes;
        }

        private static byte[] generateSignatureFile(
            List<int> apkSignatureSchemeIds,
            DigestAlgorithm manifestDigestAlgorithm,
            String createdBy,
            OutputManifestFile manifest)

        {
            Manifest sf = new Manifest();
            Attributes mainAttrs = sf.getMainAttributes();
            mainAttrs.put(Attributes.Name.SIGNATURE_VERSION, ATTRIBUTE_VALUE_SIGNATURE_VERSION);
            mainAttrs.put(ATTRIBUTE_NAME_CREATED_BY, createdBy);
            if (apkSignatureSchemeIds.Count != 0)
            {
                // Add APK Signature Scheme v2 (and newer) signature stripping protection.
                // This attribute indicates that this APK is supposed to have been signed using one or
                // more APK-specific signature schemes in addition to the standard JAR signature scheme
                // used by this code. APK signature verifier should reject the APK if it does not
                // contain a signature for the signature scheme the verifier prefers out of this set.
                StringBuilder attrValue = new StringBuilder();
                foreach (int id in apkSignatureSchemeIds)
                {
                    if (attrValue.Length > 0)
                    {
                        attrValue.Append(", ");
                    }

                    attrValue.Append(id.ToString());
                }

                mainAttrs.put(
                    SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME,
                    attrValue.ToString());
            }

            // Add main attribute containing the digest of MANIFEST.MF.
            HashAlgorithm md = getMessageDigestInstance(manifestDigestAlgorithm);
            mainAttrs.putValue(
                getManifestDigestAttributeName(manifestDigestAlgorithm),
                Convert.ToBase64String(md.ComputeHash(manifest.contents)));
            var @out = new MemoryStream();
            try
            {
                SignatureFileWriter.writeMainSection(@out, mainAttrs);
            }
            catch (IOException e)
            {
                throw new ApplicationException("Failed to write in-memory .SF file", e);
            }

            String entryDigestAttributeName = getEntryDigestAttributeName(manifestDigestAlgorithm);
            foreach (var manifestSection in manifest.individualSectionsContents)
            {
                String sectionName = manifestSection.Key;
                byte[] sectionContents = manifestSection.Value;
                byte[] sectionDigest = md.ComputeHash(sectionContents);
                Attributes attrs = new Attributes();
                attrs.putValue(
                    entryDigestAttributeName,
                    Convert.ToBase64String(sectionDigest));

                try
                {
                    SignatureFileWriter.writeIndividualSection(@out, sectionName, attrs);
                }
                catch (IOException e)
                {
                    throw new ApplicationException("Failed to write in-memory .SF file", e);
                }
            }

            // A bug in the java.util.jar implementation of Android platforms up to version 1.6 will
            // cause a spurious IOException to be thrown if the length of the signature file is a
            // multiple of 1024 bytes. As a workaround, add an extra CRLF in this case.
            if ((@out.Length > 0) && ((@out.Length % 1024) == 0))
            {
                try
                {
                    SignatureFileWriter.writeSectionDelimiter(@out);
                }
                catch (IOException e)
                {
                    throw new ApplicationException("Failed to write to ByteArrayOutputStream", e);
                }
            }

            return @out.ToArray();
        }


        /**
 * Generates the CMS PKCS #7 signature block corresponding to the provided signature file and
 * signing configuration.
 */
        private static byte[] generateSignatureBlock(
            SignerConfig signerConfig, byte[] signatureFileBytes)

        {
            // Obtain relevant bits of signing configuration
            List<X509Certificate> signerCerts = signerConfig.certificates;
            X509Certificate signingCert = signerCerts[0];
            PublicKey publicKey = signingCert.getPublicKey();
            DigestAlgorithm digestAlgorithm = signerConfig.signatureDigestAlgorithm;
            Tuple<String, AlgorithmIdentifier> signatureAlgs =
                AlgorithmIdentifier.getSignerInfoSignatureAlgorithm(publicKey, digestAlgorithm,
                    signerConfig.deterministicDsaSigning);
            String jcaSignatureAlgorithm = signatureAlgs.Item1;

            // Generate the cryptographic signature of the signature file
            byte[] signatureBytes;
            try
            {
                Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
                signature.initSign(signerConfig.privateKey);
                signature.update(signatureFileBytes);
                signatureBytes = signature.sign();
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException("Failed to sign using " + jcaSignatureAlgorithm, e);
            }

            // Verify the signature against the public key in the signing certificate
            try
            {
                Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
                signature.initVerify(publicKey);
                signature.update(signatureFileBytes);
                if (!signature.verify(signatureBytes))
                {
                    throw new CryptographicException("Signature did not verify");
                }
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException(
                    "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                    + " public key from certificate",
                    e);
            }

            AlgorithmIdentifier digestAlgorithmId =
                AlgorithmIdentifier.getSignerInfoDigestAlgorithmOid(digestAlgorithm);
            AlgorithmIdentifier signatureAlgorithmId = signatureAlgs.Item2;
            try
            {
                return ApkSigningBlockUtils.generatePkcs7DerEncodedMessage(
                    signatureBytes,
                    null,
                    signerCerts, digestAlgorithmId,
                    signatureAlgorithmId);
            }
            catch (Exception e) when (e is Asn1EncodingException || e is CryptographicException)
            {
                throw new CryptographicException("Failed to encode signature block");
            }
        }


        private static String getEntryDigestAttributeName(DigestAlgorithm digestAlgorithm)
        {
            switch (digestAlgorithm)
            {
                case DigestAlgorithm.SHA1:
                    return "SHA1-Digest";
                case DigestAlgorithm.SHA256:
                    return "SHA-256-Digest";
                default:
                    throw new ArgumentException(
                        "Unexpected content digest algorithm: " + digestAlgorithm);
            }
        }

        private static String getManifestDigestAttributeName(DigestAlgorithm digestAlgorithm)
        {
            switch (digestAlgorithm)
            {
                case DigestAlgorithm.SHA1:
                    return "SHA1-Digest-Manifest";
                case DigestAlgorithm.SHA256:
                    return "SHA-256-Digest-Manifest";
                default:
                    throw new ArgumentException(
                        "Unexpected content digest algorithm: " + digestAlgorithm);
            }
        }
    }
}