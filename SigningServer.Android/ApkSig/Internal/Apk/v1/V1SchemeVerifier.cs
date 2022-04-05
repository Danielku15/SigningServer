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
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SigningServer.Android.ApkSig;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.ApkSig.Internal.Jar;
using SigningServer.Android.ApkSig.Internal.Oid;
using SigningServer.Android.ApkSig.Internal.Pkcs7;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Internal.X509;
using SigningServer.Android.ApkSig.Internal.Zip;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;
using Attribute = System.Attribute;

namespace SigningServer.Android.ApkSig.Internal.Apk.v1
{
    /**
     * APK verifier which uses JAR signing (aka v1 signing scheme).
     *
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File">Signed JAR File</a>
     */
    public static class V1SchemeVerifier
    {
        /**
         * Verifies the provided APK's JAR signatures and returns the result of verification. APK is
         * considered verified only if {@link Result#verified} is {@code true}. If verification fails,
         * the result will contain errors -- see {@link Result#getErrors()}.
         *
         * <p>Verification succeeds iff the APK's JAR signatures are expected to verify on all Android
         * platform versions in the {@code [minSdkVersion, maxSdkVersion]} range. If the APK's signature
         * is expected to not verify on any of the specified platform versions, this method returns a
         * result with one or more errors and whose {@code Result.verified == false}, or this method
         * throws an exception.
         *
         * @throws ApkFormatException if the APK is malformed
         * @throws IOException if an I/O error occurs when reading the APK
         * @throws NoSuchAlgorithmException if the APK's JAR signatures cannot be verified because a
         *         required cryptographic algorithm implementation is missing
         */
        public static Result verify(
            DataSource apk,
            ZipSections apkSections,
            Dictionary<int, String> supportedApkSigSchemeNames,
            ISet<int> foundApkSigSchemeIds,
            int minSdkVersion,
            int maxSdkVersion)
        {
            if (minSdkVersion > maxSdkVersion)
            {
                throw new ArgumentException(
                    "minSdkVersion (" + minSdkVersion + ") > maxSdkVersion (" + maxSdkVersion
                    + ")");
            }

            Result result = new Result();

            // Parse the ZIP Central Directory and check that there are no entries with duplicate names.
            List<CentralDirectoryRecord> cdRecords = parseZipCentralDirectory(apk, apkSections);
            ISet<String> cdEntryNames = checkForDuplicateEntries(cdRecords, result);
            if (result.containsErrors())
            {
                return result;
            }

            // Verify JAR signature(s).
            Signers.verify(
                apk,
                apkSections.getZipCentralDirectoryOffset(),
                cdRecords,
                cdEntryNames,
                supportedApkSigSchemeNames,
                foundApkSigSchemeIds,
                minSdkVersion,
                maxSdkVersion,
                result);

            return result;
        }

        /**
     * Returns the set of entry names and reports any duplicate entry names in the {@code result}
     * as errors.
     */
        private static ISet<String> checkForDuplicateEntries(
            List<CentralDirectoryRecord> cdRecords, Result result)
        {
            ISet<String> cdEntryNames = new HashSet<string>(cdRecords.Count);
            ISet<String> duplicateCdEntryNames = null;
            foreach (CentralDirectoryRecord cdRecord in cdRecords)
            {
                String entryName = cdRecord.getName();
                if (!cdEntryNames.Add(entryName))
                {
                    // This is an error. Report this once per duplicate name.
                    if (duplicateCdEntryNames == null)
                    {
                        duplicateCdEntryNames = new HashSet<string>();
                    }

                    if (duplicateCdEntryNames.Add(entryName))
                    {
                        result.addError(ApkVerifier.Issue.JAR_SIG_DUPLICATE_ZIP_ENTRY, entryName);
                    }
                }
            }

            return cdEntryNames;
        }

        /**
    * Parses raw representation of MANIFEST.MF file into a pair of main entry manifest section
    * representation and a mapping between entry name and its manifest section representation.
    *
    * @param manifestBytes raw representation of Manifest.MF
    * @param cdEntryNames expected set of entry names
    * @param result object to keep track of errors that happened during the parsing
    * @return a pair of main entry manifest section representation and a mapping between entry name
    *     and its manifest section representation
    */
        public static Tuple<ManifestParser.Section, Dictionary<String, ManifestParser.Section>> parseManifest(
            byte[] manifestBytes, ISet<String> cdEntryNames, Result result)
        {
            ManifestParser manifest = new ManifestParser(manifestBytes);
            ManifestParser.Section manifestMainSection = manifest.readSection();
            List<ManifestParser.Section> manifestIndividualSections = manifest.readAllSections();
            Dictionary<String, ManifestParser.Section> entryNameToManifestSection =
                new Dictionary<String, ManifestParser.Section>(manifestIndividualSections.Count);
            int manifestSectionNumber = 0;
            foreach (ManifestParser.Section manifestSection in manifestIndividualSections)
            {
                manifestSectionNumber++;
                String entryName = manifestSection.getName();
                if (entryName == null)
                {
                    result.addError(ApkVerifier.Issue.JAR_SIG_UNNNAMED_MANIFEST_SECTION, manifestSectionNumber);
                    continue;
                }

                if (entryNameToManifestSection.ContainsKey(entryName))
                {
                    result.addError(ApkVerifier.Issue.JAR_SIG_DUPLICATE_MANIFEST_SECTION, entryName);
                    continue;
                }

                entryNameToManifestSection[entryName] = manifestSection;

                if (!cdEntryNames.Contains(entryName))
                {
                    result.addError(
                        ApkVerifier.Issue.JAR_SIG_MISSING_ZIP_ENTRY_REFERENCED_IN_MANIFEST, entryName);
                    continue;
                }
            }

            return Tuple.Create(manifestMainSection, entryNameToManifestSection);
        }

        /**
     * All JAR signers of an APK.
     */
        private static class Signers
        {
            /**
         * Verifies JAR signatures of the provided APK and populates the provided result container
         * with errors, warnings, and information about signers. The APK is considered verified if
         * the {@link Result#verified} is {@code true}.
         */
            public static void verify(
                DataSource apk,
                long cdStartOffset,
                List<CentralDirectoryRecord> cdRecords,
                ISet<String> cdEntryNames,
                Dictionary<int, String> supportedApkSigSchemeNames,
                ISet<int> foundApkSigSchemeIds,
                int minSdkVersion,
                int maxSdkVersion,
                Result result)
            {
                // Find JAR manifest and signature block files.
                CentralDirectoryRecord manifestEntry = null;
                Dictionary<String, CentralDirectoryRecord> sigFileEntries =
                    new Dictionary<String, CentralDirectoryRecord>(1);
                List<CentralDirectoryRecord> sigBlockEntries = new List<CentralDirectoryRecord>(1);
                foreach (CentralDirectoryRecord cdRecord in cdRecords)
                {
                    String entryName = cdRecord.getName();
                    if (!entryName.StartsWith("META-INF/"))
                    {
                        continue;
                    }

                    if ((manifestEntry == null) && (V1SchemeConstants.MANIFEST_ENTRY_NAME.Equals(
                            entryName)))
                    {
                        manifestEntry = cdRecord;
                        continue;
                    }

                    if (entryName.EndsWith(".SF"))
                    {
                        sigFileEntries[entryName] = cdRecord;
                        continue;
                    }

                    if ((entryName.EndsWith(".RSA"))
                        || (entryName.EndsWith(".DSA"))
                        || (entryName.EndsWith(".EC")))
                    {
                        sigBlockEntries.Add(cdRecord);
                        continue;
                    }
                }

                if (manifestEntry == null)
                {
                    result.addError(ApkVerifier.Issue.JAR_SIG_NO_MANIFEST);
                    return;
                }

                // Parse the JAR manifest and check that all JAR entries it references exist in the APK.
                byte[] manifestBytes;
                try
                {
                    manifestBytes =
                        LocalFileRecord.getUncompressedData(apk, manifestEntry, cdStartOffset);
                }
                catch (ZipFormatException e)
                {
                    throw new ApkFormatException("Malformed ZIP entry: " + manifestEntry.getName(), e);
                }

                Tuple<ManifestParser.Section, Dictionary<String, ManifestParser.Section>> manifestSections =
                    parseManifest(manifestBytes, cdEntryNames, result);

                if (result.containsErrors())
                {
                    return;
                }

                ManifestParser.Section manifestMainSection = manifestSections.Item1;
                Dictionary<String, ManifestParser.Section> entryNameToManifestSection =
                    manifestSections.Item2;

                // STATE OF AFFAIRS:
                // * All JAR entries listed in JAR manifest are present in the APK.

                // Identify signers
                List<Signer> signers = new List<Signer>(sigBlockEntries.Count);
                foreach (CentralDirectoryRecord sigBlockEntry in sigBlockEntries)
                {
                    String sigBlockEntryName = sigBlockEntry.getName();
                    int extensionDelimiterIndex = sigBlockEntryName.LastIndexOf('.');
                    if (extensionDelimiterIndex == -1)
                    {
                        throw new ApplicationException(
                            "Signature block file name does not contain extension: "
                            + sigBlockEntryName);
                    }

                    String sigFileEntryName =
                        sigBlockEntryName.Substring(0, extensionDelimiterIndex) + ".SF";
                    sigFileEntries.TryGetValue(sigFileEntryName, out var sigFileEntry);
                    if (sigFileEntry == null)
                    {
                        result.addWarning(
                            ApkVerifier.Issue.JAR_SIG_MISSING_FILE, sigBlockEntryName, sigFileEntryName);
                        continue;
                    }

                    String signerName = sigBlockEntryName.Substring("META-INF/".Length);
                    Result.SignerInfo signerInfo =
                        new Result.SignerInfo(
                            signerName, sigBlockEntryName, sigFileEntry.getName());
                    Signer signer = new Signer(signerName, sigBlockEntry, sigFileEntry, signerInfo);
                    signers.Add(signer);
                }

                if (signers.Count == 0)
                {
                    result.addError(ApkVerifier.Issue.JAR_SIG_NO_SIGNATURES);
                    return;
                }

                // Verify each signer's signature block file .(RSA|DSA|EC) against the corresponding
                // signature file .SF. Any error encountered for any signer terminates verification, to
                // mimic Android's behavior.
                foreach (Signer signer in signers)
                {
                    signer.verifySigBlockAgainstSigFile(
                        apk, cdStartOffset, minSdkVersion, maxSdkVersion);
                    if (signer.getResult().containsErrors())
                    {
                        result.signers.Add(signer.getResult());
                    }
                }

                if (result.containsErrors())
                {
                    return;
                }
                // STATE OF AFFAIRS:
                // * All JAR entries listed in JAR manifest are present in the APK.
                // * All signature files (.SF) verify against corresponding block files (.RSA|.DSA|.EC).

                // Verify each signer's signature file (.SF) against the JAR manifest.
                List<Signer> remainingSigners = new List<Signer>(signers.Count);
                foreach (Signer signer in signers)
                {
                    signer.verifySigFileAgainstManifest(
                        manifestBytes,
                        manifestMainSection,
                        entryNameToManifestSection,
                        supportedApkSigSchemeNames,
                        foundApkSigSchemeIds,
                        minSdkVersion,
                        maxSdkVersion);
                    if (signer.isIgnored())
                    {
                        result.ignoredSigners.Add(signer.getResult());
                    }
                    else
                    {
                        if (signer.getResult().containsErrors())
                        {
                            result.signers.Add(signer.getResult());
                        }
                        else
                        {
                            remainingSigners.Add(signer);
                        }
                    }
                }

                if (result.containsErrors())
                {
                    return;
                }

                signers = remainingSigners;
                if (signers.Count == 0)
                {
                    result.addError(ApkVerifier.Issue.JAR_SIG_NO_SIGNATURES);
                    return;
                }
                // STATE OF AFFAIRS:
                // * All signature files (.SF) verify against corresponding block files (.RSA|.DSA|.EC).
                // * Contents of all JAR manifest sections listed in .SF files verify against .SF files.
                // * All JAR entries listed in JAR manifest are present in the APK.

                // Verify data of JAR entries against JAR manifest and .SF files. On Android, an APK's
                // JAR entry is considered signed by signers associated with an .SF file iff the entry
                // is mentioned in the .SF file and the entry's digest(s) mentioned in the JAR manifest
                // match theentry's uncompressed data. Android requires that all such JAR entries are
                // signed by the same set of signers. This set may be smaller than the set of signers
                // we've identified so far.
                ISet<Signer> apkSigners =
                    verifyJarEntriesAgainstManifestAndSigners(
                        apk,
                        cdStartOffset,
                        cdRecords,
                        entryNameToManifestSection,
                        signers,
                        minSdkVersion,
                        maxSdkVersion,
                        result);
                if (result.containsErrors())
                {
                    return;
                }
                // STATE OF AFFAIRS:
                // * All signature files (.SF) verify against corresponding block files (.RSA|.DSA|.EC).
                // * Contents of all JAR manifest sections listed in .SF files verify against .SF files.
                // * All JAR entries listed in JAR manifest are present in the APK.
                // * All JAR entries present in the APK and supposed to be covered by JAR signature
                //   (i.e., reside outside of META-INF/) are covered by signatures from the same set
                //   of signers.

                // Report any JAR entries which aren't covered by signature.
                ISet<String> signatureEntryNames = new HashSet<string>(1 + result.signers.Count * 2);
                signatureEntryNames.Add(manifestEntry.getName());
                foreach (Signer signer in apkSigners)
                {
                    signatureEntryNames.Add(signer.getSignatureBlockEntryName());
                    signatureEntryNames.Add(signer.getSignatureFileEntryName());
                }

                foreach (CentralDirectoryRecord cdRecord in cdRecords)
                {
                    String entryName = cdRecord.getName();
                    if ((entryName.StartsWith("META-INF/"))
                        && (!entryName.EndsWith("/"))
                        && (!signatureEntryNames.Contains(entryName)))
                    {
                        result.addWarning(ApkVerifier.Issue.JAR_SIG_UNPROTECTED_ZIP_ENTRY, entryName);
                    }
                }

                // Reflect the sets of used signers and ignored signers in the result.
                foreach (Signer signer in signers)
                {
                    if (apkSigners.Contains(signer))
                    {
                        result.signers.Add(signer.getResult());
                    }
                    else
                    {
                        result.ignoredSigners.Add(signer.getResult());
                    }
                }

                result.verified = true;
            }
        }

        class Signer
        {
            private readonly String mName;
            private readonly Result.SignerInfo mResult;
            private readonly CentralDirectoryRecord mSignatureFileEntry;
            private readonly CentralDirectoryRecord mSignatureBlockEntry;
            private bool mIgnored;

            private byte[] mSigFileBytes;
            private ISet<String> mSigFileEntryNames;

            public Signer(
                String name,
                CentralDirectoryRecord sigBlockEntry,
                CentralDirectoryRecord sigFileEntry,
                Result.SignerInfo result)
            {
                mName = name;
                mResult = result;
                mSignatureBlockEntry = sigBlockEntry;
                mSignatureFileEntry = sigFileEntry;
            }

            public String getName()
            {
                return mName;
            }

            public String getSignatureFileEntryName()
            {
                return mSignatureFileEntry.getName();
            }

            public String getSignatureBlockEntryName()
            {
                return mSignatureBlockEntry.getName();
            }

            void setIgnored()
            {
                mIgnored = true;
            }

            public bool isIgnored()
            {
                return mIgnored;
            }

            public ISet<String> getSigFileEntryNames()
            {
                return mSigFileEntryNames;
            }

            public Result.SignerInfo getResult()
            {
                return mResult;
            }

            public void verifySigBlockAgainstSigFile(
                DataSource apk, long cdStartOffset, int minSdkVersion, int maxSdkVersion)

            {
                // Obtain the signature block from the APK
                byte[] sigBlockBytes;
                try
                {
                    sigBlockBytes =
                        LocalFileRecord.getUncompressedData(
                            apk, mSignatureBlockEntry, cdStartOffset);
                }
                catch (ZipFormatException e)
                {
                    throw new ApkFormatException(
                        "Malformed ZIP entry: " + mSignatureBlockEntry.getName(), e);
                }

                // Obtain the signature file from the APK
                try
                {
                    mSigFileBytes =
                        LocalFileRecord.getUncompressedData(
                            apk, mSignatureFileEntry, cdStartOffset);
                }
                catch (ZipFormatException e)
                {
                    throw new ApkFormatException(
                        "Malformed ZIP entry: " + mSignatureFileEntry.getName(), e);
                }

                // Extract PKCS #7 SignedData from the signature block
                SignedData signedData;
                try
                {
                    ContentInfo contentInfo =
                        Asn1BerParser.parse<ContentInfo>(ByteBuffer.wrap(sigBlockBytes));
                    if (!Pkcs7Constants.OID_SIGNED_DATA.Equals(contentInfo.contentType))
                    {
                        throw new Asn1DecodingException(
                            "Unsupported ContentInfo.contentType: " + contentInfo.contentType);
                    }

                    signedData =
                        Asn1BerParser.parse<SignedData>(contentInfo.content.getEncoded());
                }
                catch (Asn1DecodingException e)
                {
                    mResult.addError(
                        ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION, mSignatureBlockEntry.getName(), e);
                    return;
                }

                if (signedData.signerInfos.Count == 0)
                {
                    mResult.addError(ApkVerifier.Issue.JAR_SIG_NO_SIGNERS, mSignatureBlockEntry.getName());
                    return;
                }

                // Find the first SignedData.SignerInfos element which verifies against the signature
                // file
                SignerInfo firstVerifiedSignerInfo = null;
                X509Certificate firstVerifiedSignerInfoSigningCertificate = null;
                // Prior to Android N, Android attempts to verify only the first SignerInfo. From N
                // onwards, Android attempts to verify all SignerInfos and then picks the first verified
                // SignerInfo.
                List<SignerInfo> unverifiedSignerInfosToTry;
                if (minSdkVersion < AndroidSdkVersion.N)
                {
                    unverifiedSignerInfosToTry =
                        new List<SignerInfo>
                        {
                            signedData.signerInfos[0]
                        };
                }
                else
                {
                    unverifiedSignerInfosToTry = signedData.signerInfos;
                }

                List<X509Certificate> signedDataCertificates = null;
                foreach (SignerInfo unverifiedSignerInfo in unverifiedSignerInfosToTry)
                {
                    // Parse SignedData.certificates -- they are needed to verify SignerInfo
                    if (signedDataCertificates == null)
                    {
                        try
                        {
                            signedDataCertificates = Certificate.parseCertificates(signedData.certificates);
                        }
                        catch (CryptographicException e)
                        {
                            mResult.addError(
                                ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION, mSignatureBlockEntry.getName(), e);
                            return;
                        }
                    }

                    // Verify SignerInfo
                    X509Certificate signingCertificate;
                    try
                    {
                        signingCertificate =
                            verifySignerInfoAgainstSigFile(
                                signedData,
                                signedDataCertificates,
                                unverifiedSignerInfo,
                                mSigFileBytes,
                                minSdkVersion,
                                maxSdkVersion);
                        if (mResult.containsErrors())
                        {
                            return;
                        }

                        if (signingCertificate != null)
                        {
                            // SignerInfo verified
                            if (firstVerifiedSignerInfo == null)
                            {
                                firstVerifiedSignerInfo = unverifiedSignerInfo;
                                firstVerifiedSignerInfoSigningCertificate = signingCertificate;
                            }
                        }
                    }
                    catch (Pkcs7DecodingException e)
                    {
                        mResult.addError(
                            ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION, mSignatureBlockEntry.getName(), e);
                        return;
                    }
                    catch (Exception e) when (e is CryptographicException)
                    {
                        mResult.addError(
                            ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION,
                            mSignatureBlockEntry.getName(),
                            mSignatureFileEntry.getName(),
                            e);
                        return;
                    }
                }

                if (firstVerifiedSignerInfo == null)
                {
                    // No SignerInfo verified
                    mResult.addError(
                        ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY,
                        mSignatureBlockEntry.getName(),
                        mSignatureFileEntry.getName());
                    return;
                }

                // Verified
                List<X509Certificate> signingCertChain =
                    getCertificateChain(
                        signedDataCertificates, firstVerifiedSignerInfoSigningCertificate);
                mResult.certChain.Clear();
                mResult.certChain.AddRange(signingCertChain);
            }

            /**
         * Returns the signing certificate if the provided {@link SignerInfo} verifies against the
         * contents of the provided signature file, or {@code null} if it does not verify.
         */
            private X509Certificate verifySignerInfoAgainstSigFile(
                SignedData signedData,
                IList<X509Certificate> signedDataCertificates,
                SignerInfo signerInfo,
                byte[] signatureFile,
                int minSdkVersion,
                int maxSdkVersion)

            {
                String digestAlgorithmOid = signerInfo.digestAlgorithm.algorithm;
                String signatureAlgorithmOid = signerInfo.signatureAlgorithm.algorithm;
                InclusiveIntRange desiredApiLevels =
                    InclusiveIntRange.fromTo(minSdkVersion, maxSdkVersion);
                List<InclusiveIntRange> apiLevelsWhereDigestAndSigAlgorithmSupported =
                    OidConstants.getSigAlgSupportedApiLevels(digestAlgorithmOid, signatureAlgorithmOid);
                List<InclusiveIntRange> apiLevelsWhereDigestAlgorithmNotSupported =
                    desiredApiLevels.getValuesNotIn(apiLevelsWhereDigestAndSigAlgorithmSupported);
                if (apiLevelsWhereDigestAlgorithmNotSupported.Count != 0)
                {
                    String digestAlgorithmUserFriendly =
                        OidConstants.OidToUserFriendlyNameMapper.getUserFriendlyNameForOid(
                            digestAlgorithmOid);
                    if (digestAlgorithmUserFriendly == null)
                    {
                        digestAlgorithmUserFriendly = digestAlgorithmOid;
                    }

                    String signatureAlgorithmUserFriendly =
                        OidConstants.OidToUserFriendlyNameMapper.getUserFriendlyNameForOid(
                            signatureAlgorithmOid);
                    if (signatureAlgorithmUserFriendly == null)
                    {
                        signatureAlgorithmUserFriendly = signatureAlgorithmOid;
                    }

                    StringBuilder apiLevelsUserFriendly = new StringBuilder();
                    foreach (InclusiveIntRange range in apiLevelsWhereDigestAlgorithmNotSupported)
                    {
                        if (apiLevelsUserFriendly.Length > 0)
                        {
                            apiLevelsUserFriendly.Append(", ");
                        }

                        if (range.getMin() == range.getMax())
                        {
                            apiLevelsUserFriendly.Append(range.getMin());
                        }
                        else if (range.getMax() == int.MaxValue)
                        {
                            apiLevelsUserFriendly.Append(range.getMin() + "+");
                        }
                        else
                        {
                            apiLevelsUserFriendly.Append(range.getMin() + "-" + range.getMax());
                        }
                    }

                    mResult.addError(
                        ApkVerifier.Issue.JAR_SIG_UNSUPPORTED_SIG_ALG,
                        mSignatureBlockEntry.getName(),
                        digestAlgorithmOid,
                        signatureAlgorithmOid,
                        apiLevelsUserFriendly.ToString(),
                        digestAlgorithmUserFriendly,
                        signatureAlgorithmUserFriendly);
                    return null;
                }

                // From the bag of certs, obtain the certificate referenced by the SignerInfo,
                // and verify the cryptographic signature in the SignerInfo against the certificate.

                // Locate the signing certificate referenced by the SignerInfo
                X509Certificate signingCertificate =
                    Certificate.findCertificate(signedDataCertificates, signerInfo.sid);
                if (signingCertificate == null)
                {
                    throw new CryptographicException(
                        "Signing certificate referenced in SignerInfo not found in"
                        + " SignedData");
                }

                // Check whether the signing certificate is acceptable. Android performs these
                // checks explicitly, instead of delegating this to
                // Signature.initVerify(Certificate).
                if (signingCertificate.hasUnsupportedCriticalExtension())
                {
                    throw new CryptographicException(
                        "Signing certificate has unsupported critical extensions");
                }

                bool[] keyUsageExtension = signingCertificate.getKeyUsage();
                if (keyUsageExtension != null)
                {
                    bool digitalSignature =
                        (keyUsageExtension.Length >= 1) && (keyUsageExtension[0]);
                    bool nonRepudiation =
                        (keyUsageExtension.Length >= 2) && (keyUsageExtension[1]);
                    if ((!digitalSignature) && (!nonRepudiation))
                    {
                        throw new CryptographicException(
                            "Signing certificate not authorized for use in digital signatures"
                            + ": keyUsage extension missing digitalSignature and"
                            + " nonRepudiation");
                    }
                }

                // Verify the cryptographic signature in SignerInfo against the certificate's
                // public key
                String jcaSignatureAlgorithm =
                    AlgorithmIdentifier.getJcaSignatureAlgorithm(digestAlgorithmOid, signatureAlgorithmOid);
                Signature s = Signature.getInstance(jcaSignatureAlgorithm);
                s.initVerify(signingCertificate.getPublicKey());
                if (signerInfo.signedAttrs != null)
                {
                    // Signed attributes present -- verify signature against the ASN.1 DER encoded form
                    // of signed attributes. This verifies integrity of the signature file because
                    // signed attributes must contain the digest of the signature file.
                    if (minSdkVersion < AndroidSdkVersion.KITKAT)
                    {
                        // Prior to Android KitKat, APKs with signed attributes are unsafe:
                        // * The APK's contents are not protected by the JAR signature because the
                        //   digest in signed attributes is not verified. This means an attacker can
                        //   arbitrarily modify the APK without invalidating its signature.
                        // * Luckily, the signature over signed attributes was verified incorrectly
                        //   (over the verbatim IMPLICIT [0] form rather than over re-encoded
                        //   UNIVERSAL SET form) which means that JAR signatures which would verify on
                        //   pre-KitKat Android and yet do not protect the APK from modification could
                        //   be generated only by broken tools or on purpose by the entity signing the
                        //   APK.
                        //
                        // We thus reject such unsafe APKs, even if they verify on platforms before
                        // KitKat.
                        throw new CryptographicException(
                            "APKs with Signed Attributes broken on platforms with API Level < "
                            + AndroidSdkVersion.KITKAT);
                    }

                    try
                    {
                        List<Pkcs7.Attribute> signedAttributes =
                            Asn1BerParser.parseImplicitSetOf<Pkcs7.Attribute>(
                                signerInfo.signedAttrs.getEncoded());
                        SignedAttributes signedAttrs = new SignedAttributes(signedAttributes);
                        if (maxSdkVersion >= AndroidSdkVersion.N)
                        {
                            // Content Type attribute is checked only on Android N and newer
                            String contentType =
                                signedAttrs.getSingleObjectIdentifierValue(
                                    Pkcs7Constants.OID_CONTENT_TYPE);
                            if (contentType == null)
                            {
                                throw new CryptographicException("No Content Type in signed attributes");
                            }

                            if (!contentType.Equals(signedData.encapContentInfo.contentType))
                            {
                                // Did not verify: Content type signed attribute does not match
                                // SignedData.encapContentInfo.eContentType. This fails verification of
                                // this SignerInfo but should not prevent verification of other
                                // SignerInfos. Hence, no exception is thrown.
                                return null;
                            }
                        }

                        byte[] expectedSignatureFileDigest =
                            signedAttrs.getSingleOctetStringValue(
                                Pkcs7Constants.OID_MESSAGE_DIGEST);
                        if (expectedSignatureFileDigest == null)
                        {
                            throw new CryptographicException("No content digest in signed attributes");
                        }

                        byte[] actualSignatureFileDigest =
                            HashAlgorithm.Create(
                                    AlgorithmIdentifier.getJcaDigestAlgorithm(digestAlgorithmOid))
                                .ComputeHash(signatureFile);
                        if (!expectedSignatureFileDigest.SequenceEqual(actualSignatureFileDigest))
                        {
                            // Skip verification: signature file digest in signed attributes does not
                            // match the signature file. This fails verification of
                            // this SignerInfo but should not prevent verification of other
                            // SignerInfos. Hence, no exception is thrown.
                            return null;
                        }
                    }
                    catch (Asn1DecodingException e)
                    {
                        throw new CryptographicException("Failed to parse signed attributes", e);
                    }

                    // PKCS #7 requires that signature is over signed attributes re-encoded as
                    // ASN.1 DER. However, Android does not re-encode except for changing the
                    // first byte of encoded form from IMPLICIT [0] to UNIVERSAL SET. We do the
                    // same for maximum compatibility.
                    ByteBuffer signedAttrsOriginalEncoding = signerInfo.signedAttrs.getEncoded();
                    s.update((byte)0x31); // UNIVERSAL SET
                    signedAttrsOriginalEncoding.position(1);
                    s.update(signedAttrsOriginalEncoding);
                }
                else
                {
                    // No signed attributes present -- verify signature against the contents of the
                    // signature file
                    s.update(signatureFile);
                }

                byte[] sigBytes = ByteBufferUtils.toByteArray(signerInfo.signature.slice());
                if (!s.verify(sigBytes))
                {
                    // Cryptographic signature did not verify. This fails verification of this
                    // SignerInfo but should not prevent verification of other SignerInfos. Hence, no
                    // exception is thrown.
                    return null;
                }

                // Cryptographic signature verified
                return signingCertificate;
            }


            public static List<X509Certificate> getCertificateChain(
                List<X509Certificate> certs, X509Certificate leaf)
            {
                List<X509Certificate> unusedCerts = new List<X509Certificate>(certs);
                List<X509Certificate> result = new List<X509Certificate>(1);
                result.Add(leaf);
                unusedCerts.Remove(leaf);
                X509Certificate root = leaf;
                while (!root.getSubjectDN().Equals(root.getIssuerDN()))
                {
                    var targetDn = root.getIssuerDN();
                    bool issuerFound = false;
                    for (int i = 0; i < unusedCerts.Count; i++)
                    {
                        X509Certificate unusedCert = unusedCerts[i];
                        if (targetDn.Equals(unusedCert.getSubjectDN()))
                        {
                            issuerFound = true;
                            unusedCerts.RemoveAt(i);
                            result.Add(unusedCert);
                            root = unusedCert;
                            break;
                        }
                    }

                    if (!issuerFound)
                    {
                        break;
                    }
                }

                return result;
            }


            public void verifySigFileAgainstManifest(
                byte[] manifestBytes,
                ManifestParser.Section manifestMainSection,
                Dictionary<String, ManifestParser.Section> entryNameToManifestSection,
                Dictionary<int, String> supportedApkSigSchemeNames,
                ISet<int> foundApkSigSchemeIds,
                int minSdkVersion,
                int maxSdkVersion)
            {
                // Inspect the main section of the .SF file.
                ManifestParser sf = new ManifestParser(mSigFileBytes);

                ManifestParser.Section sfMainSection = sf.readSection();
                if (sfMainSection.getAttributeValue(Attributes.Name.SIGNATURE_VERSION) == null)
                {
                    mResult.addError(
                        ApkVerifier.Issue.JAR_SIG_MISSING_VERSION_ATTR_IN_SIG_FILE,
                        mSignatureFileEntry.getName());
                    setIgnored();
                    return;
                }

                if (maxSdkVersion >= AndroidSdkVersion.N)
                {
                    // Android N and newer rejects APKs whose .SF file says they were supposed to be
                    // signed with APK Signature Scheme v2 (or newer) and yet no such signature was
                    // found.
                    checkForStrippedApkSignatures(
                        sfMainSection, supportedApkSigSchemeNames, foundApkSigSchemeIds);
                    if (mResult.containsErrors())
                    {
                        return;
                    }
                }

                bool createdBySigntool = false;

                String createdBy = sfMainSection.getAttributeValue("Created-By");
                if (createdBy != null)
                {
                    createdBySigntool = createdBy.IndexOf("signtool") != -1;
                }

                bool manifestDigestVerified =
                    verifyManifestDigest(
                        sfMainSection,
                        createdBySigntool,
                        manifestBytes,
                        minSdkVersion,
                        maxSdkVersion);
                if (!createdBySigntool)
                {
                    verifyManifestMainSectionDigest(
                        sfMainSection,
                        manifestMainSection,
                        manifestBytes,
                        minSdkVersion,
                        maxSdkVersion);
                }

                if (mResult.containsErrors())
                {
                    return;
                }

                // Inspect per-entry sections of .SF file. Technically, if the digest of JAR manifest
                // verifies, per-entry sections should be ignored. However, most Android platform
                // implementations require that such sections exist.
                List<ManifestParser.Section> sfSections = sf.readAllSections();
                ISet<String> sfEntryNames = new HashSet<string>(sfSections.Count);
                int sfSectionNumber = 0;
                foreach (ManifestParser.Section sfSection in sfSections)
                {
                    sfSectionNumber++;
                    String entryName = sfSection.getName();
                    if (entryName == null)
                    {
                        mResult.addError(
                            ApkVerifier.Issue.JAR_SIG_UNNNAMED_SIG_FILE_SECTION,
                            mSignatureFileEntry.getName(),
                            sfSectionNumber);
                        setIgnored();
                        return;
                    }

                    if (!sfEntryNames.Add(entryName))
                    {
                        mResult.addError(
                            ApkVerifier.Issue.JAR_SIG_DUPLICATE_SIG_FILE_SECTION,
                            mSignatureFileEntry.getName(),
                            entryName);
                        setIgnored();
                        return;
                    }

                    if (manifestDigestVerified)
                    {
                        // No need to verify this entry's corresponding JAR manifest entry because the
                        // JAR manifest verifies in full.
                        continue;
                    }

                    // Whole-file digest of JAR manifest hasn't been verified. Thus, we need to verify
                    // the digest of the JAR manifest section corresponding to this .SF section.
                    entryNameToManifestSection.TryGetValue(entryName, out var manifestSection);
                    if (manifestSection == null)
                    {
                        mResult.addError(
                            ApkVerifier.Issue.JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_SIG_FILE,
                            entryName,
                            mSignatureFileEntry.getName());
                        setIgnored();
                        continue;
                    }

                    verifyManifestIndividualSectionDigest(
                        sfSection,
                        createdBySigntool,
                        manifestSection,
                        manifestBytes,
                        minSdkVersion,
                        maxSdkVersion);
                }

                mSigFileEntryNames = sfEntryNames;
            }


            /**
 * Returns {@code true} if the whole-file digest of the manifest against the main section of
 * the .SF file.
 */
            private bool verifyManifestDigest(
                ManifestParser.Section sfMainSection,
                bool createdBySigntool,
                byte[] manifestBytes,
                int minSdkVersion,
                int maxSdkVersion)

            {
                List<NamedDigest> expectedDigests =
                    getDigestsToVerify(
                        sfMainSection,
                        ((createdBySigntool) ? "-Digest" : "-Digest-Manifest"),
                        minSdkVersion,
                        maxSdkVersion);
                bool digestFound = expectedDigests.Count != 0;
                if (!digestFound)
                {
                    mResult.addWarning(
                        ApkVerifier.Issue.JAR_SIG_NO_MANIFEST_DIGEST_IN_SIG_FILE,
                        mSignatureFileEntry.getName());
                    return false;
                }

                bool verified = true;
                foreach (NamedDigest expectedDigest in expectedDigests)
                {
                    String jcaDigestAlgorithm = expectedDigest.jcaDigestAlgorithm;
                    byte[] actual = digest(jcaDigestAlgorithm, manifestBytes);
                    byte[] expected = expectedDigest.digest;
                    if (!expected.SequenceEqual(actual))
                    {
                        mResult.addWarning(
                            ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY,
                            V1SchemeConstants.MANIFEST_ENTRY_NAME,
                            jcaDigestAlgorithm,
                            mSignatureFileEntry.getName(),
                            Convert.ToBase64String(actual),
                            Convert.ToBase64String(expected));
                        verified = false;
                    }
                }

                return verified;
            }

            /**
 * Verifies the digest of the manifest's main section against the main section of the .SF
 * file.
 */
            private void verifyManifestMainSectionDigest(
                ManifestParser.Section sfMainSection,
                ManifestParser.Section manifestMainSection,
                byte[] manifestBytes,
                int minSdkVersion,
                int maxSdkVersion)

            {
                List<NamedDigest> expectedDigests =
                    getDigestsToVerify(
                        sfMainSection,
                        "-Digest-Manifest-Main-Attributes",
                        minSdkVersion,
                        maxSdkVersion);
                if (expectedDigests.Count == 0)
                {
                    return;
                }

                foreach (NamedDigest expectedDigest in expectedDigests)
                {
                    String jcaDigestAlgorithm = expectedDigest.jcaDigestAlgorithm;
                    byte[] actual =
                        digest(
                            jcaDigestAlgorithm,
                            manifestBytes,
                            manifestMainSection.getStartOffset(),
                            manifestMainSection.getSizeBytes());
                    byte[] expected = expectedDigest.digest;
                    if (!expected.SequenceEqual(actual))
                    {
                        mResult.addError(
                            ApkVerifier.Issue.JAR_SIG_MANIFEST_MAIN_SECTION_DIGEST_DID_NOT_VERIFY,
                            jcaDigestAlgorithm,
                            mSignatureFileEntry.getName(),
                            Convert.ToBase64String(actual),
                            Convert.ToBase64String(expected));
                    }
                }
            }

            /**
 * Verifies the digest of the manifest's individual section against the corresponding
 * individual section of the .SF file.
 */
            private void verifyManifestIndividualSectionDigest(
                ManifestParser.Section sfIndividualSection,
                bool createdBySigntool,
                ManifestParser.Section manifestIndividualSection,
                byte[] manifestBytes,
                int minSdkVersion,
                int maxSdkVersion)

            {
                String entryName = sfIndividualSection.getName();
                List<NamedDigest> expectedDigests =
                    getDigestsToVerify(
                        sfIndividualSection, "-Digest", minSdkVersion, maxSdkVersion);
                if (expectedDigests.Count == 0)
                {
                    mResult.addError(
                        ApkVerifier.Issue.JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_SIG_FILE,
                        entryName,
                        mSignatureFileEntry.getName());
                    return;
                }

                int sectionStartIndex = manifestIndividualSection.getStartOffset();
                int sectionSizeBytes = manifestIndividualSection.getSizeBytes();
                if (createdBySigntool)
                {
                    int sectionEndIndex = sectionStartIndex + sectionSizeBytes;
                    if ((manifestBytes[sectionEndIndex - 1] == '\n')
                        && (manifestBytes[sectionEndIndex - 2] == '\n'))
                    {
                        sectionSizeBytes--;
                    }
                }

                foreach (NamedDigest expectedDigest in expectedDigests)
                {
                    String jcaDigestAlgorithm = expectedDigest.jcaDigestAlgorithm;
                    byte[] actual =
                        digest(
                            jcaDigestAlgorithm,
                            manifestBytes,
                            sectionStartIndex,
                            sectionSizeBytes);
                    byte[] expected = expectedDigest.digest;
                    if (!expected.SequenceEqual(actual))
                    {
                        mResult.addError(
                            ApkVerifier.Issue.JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY,
                            entryName,
                            jcaDigestAlgorithm,
                            mSignatureFileEntry.getName(),
                            Convert.ToBase64String(actual),
                            Convert.ToBase64String(expected));
                    }
                }
            }

            private void checkForStrippedApkSignatures(
                ManifestParser.Section sfMainSection,
                Dictionary<int, String> supportedApkSigSchemeNames,
                ISet<int> foundApkSigSchemeIds)
            {
                String signedWithApkSchemes =
                    sfMainSection.getAttributeValue(
                        V1SchemeConstants.SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME_STR);
                // This field contains a comma-separated list of APK signature scheme IDs which were
                // used to sign this APK. Android rejects APKs where an ID is known to the platform but
                // the APK didn't verify using that scheme.

                if (signedWithApkSchemes == null)
                {
                    // APK signature (e.g., v2 scheme) stripping protections not enabled.
                    if (foundApkSigSchemeIds.Count != 0)
                    {
                        // APK is signed with an APK signature scheme such as v2 scheme.
                        mResult.addWarning(
                            ApkVerifier.Issue.JAR_SIG_NO_APK_SIG_STRIP_PROTECTION,
                            mSignatureFileEntry.getName());
                    }

                    return;
                }

                if (supportedApkSigSchemeNames.Count == 0)
                {
                    return;
                }

                var supportedApkSigSchemeIds = supportedApkSigSchemeNames.Keys;
                ISet<int> supportedExpectedApkSigSchemeIds = new HashSet<int>(1);
                var tokenizer = new Queue<string>(signedWithApkSchemes.Split(','));
                while (tokenizer.Count > 0)
                {
                    String idText = tokenizer.Dequeue().Trim();
                    if (idText.Length == 0)
                    {
                        continue;
                    }

                    int id;
                    try
                    {
                        id = int.Parse(idText);
                    }
                    catch (Exception ignored)
                    {
                        continue;
                    }

                    // This APK was supposed to be signed with the APK signature scheme having
                    // this ID.
                    if (supportedApkSigSchemeIds.Contains(id))
                    {
                        supportedExpectedApkSigSchemeIds.Add(id);
                    }
                    else
                    {
                        mResult.addWarning(
                            ApkVerifier.Issue.JAR_SIG_UNKNOWN_APK_SIG_SCHEME_ID,
                            mSignatureFileEntry.getName(),
                            id);
                    }
                }

                foreach (int id in supportedExpectedApkSigSchemeIds)
                {
                    if (!foundApkSigSchemeIds.Contains(id))
                    {
                        String apkSigSchemeName = supportedApkSigSchemeNames[id];
                        mResult.addError(
                            ApkVerifier.Issue.JAR_SIG_MISSING_APK_SIG_REFERENCED,
                            mSignatureFileEntry.getName(),
                            id,
                            apkSigSchemeName);
                    }
                }
            }
        }

        public static List<NamedDigest> getDigestsToVerify(
            ManifestParser.Section section,
            String digestAttrSuffix,
            int minSdkVersion,
            int maxSdkVersion)
        {
            List<NamedDigest> result = new List<NamedDigest>(1);
            if (minSdkVersion < AndroidSdkVersion.JELLY_BEAN_MR2)
            {
                // Prior to JB MR2, Android platform's logic for picking a digest algorithm to verify is
                // to rely on the ancient Digest-Algorithms attribute which contains
                // whitespace-separated list of digest algorithms (defaulting to SHA-1) to try. The
                // first digest attribute (with supported digest algorithm) found using the list is
                // used.
                String algs = section.getAttributeValue("Digest-Algorithms");
                if (algs == null)
                {
                    algs = "SHA SHA1";
                }

                var tokens = new Queue<string>(algs.Split(' ', '\t', '\n', '\r', '\f'));
                while (tokens.Count > 0)
                {
                    String alg = tokens.Dequeue();
                    String attrName = alg + digestAttrSuffix;
                    String digestBase64 = section.getAttributeValue(attrName);
                    if (digestBase64 == null)
                    {
                        // Attribute not found
                        continue;
                    }

                    alg = getCanonicalJcaMessageDigestAlgorithm(alg);
                    if ((alg == null)
                        || (getMinSdkVersionFromWhichSupportedInManifestOrSignatureFile(alg)
                            > minSdkVersion))
                    {
                        // Unsupported digest algorithm
                        continue;
                    }

                    // Supported digest algorithm
                    result.Add(new NamedDigest(alg, Convert.FromBase64String(digestBase64)));
                    break;
                }

                // No supported digests found -- this will fail to verify on pre-JB MR2 Androids.
                if (result.Count == 0)
                {
                    return result;
                }
            }

            if (maxSdkVersion >= AndroidSdkVersion.JELLY_BEAN_MR2)
            {
                // On JB MR2 and newer, Android platform picks the strongest algorithm out of:
                // SHA-512, SHA-384, SHA-256, SHA-1.
                foreach (String alg in JB_MR2_AND_NEWER_DIGEST_ALGS)
                {
                    String attrName = getJarDigestAttributeName(alg, digestAttrSuffix);
                    String digestBase64 = section.getAttributeValue(attrName);
                    if (digestBase64 == null)
                    {
                        // Attribute not found
                        continue;
                    }

                    byte[] digest = Convert.FromBase64String(digestBase64);
                    byte[] digestInResult = getDigest(result, alg);
                    if ((digestInResult == null) || (!digestInResult.SequenceEqual(digest)))
                    {
                        result.Add(new NamedDigest(alg, digest));
                    }

                    break;
                }
            }

            return result;
        }

        private static readonly String[] JB_MR2_AND_NEWER_DIGEST_ALGS =
        {
            "SHA-512",
            "SHA-384",
            "SHA-256",
            "SHA-1",
        };

        private static String getCanonicalJcaMessageDigestAlgorithm(String algorithm)
        {
            return UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL.TryGetValue(algorithm.ToUpperInvariant(), out var val)
                ? val
                : null;
        }

        public static int getMinSdkVersionFromWhichSupportedInManifestOrSignatureFile(
            String jcaAlgorithmName)
        {
            var result = MIN_SDK_VESION_FROM_WHICH_DIGEST_SUPPORTED_IN_MANIFEST.TryGetValue(
                jcaAlgorithmName.ToUpperInvariant(), out var v);
            return (result) ? v : int.MaxValue;
        }

        private static String getJarDigestAttributeName(
            String jcaDigestAlgorithm, String attrNameSuffix)
        {
            if ("SHA-1".Equals(jcaDigestAlgorithm, StringComparison.OrdinalIgnoreCase))
            {
                return "SHA1" + attrNameSuffix;
            }
            else
            {
                return jcaDigestAlgorithm + attrNameSuffix;
            }
        }

        private static readonly Dictionary<String, String>
            UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL = new Dictionary<string, string>
            {
                ["MD5"] = "MD5",
                ["SHA"] = "SHA-1",
                ["SHA1"] = "SHA-1",
                ["SHA-1"] = "SHA-1",
                ["SHA-256"] = "SHA-256",
                ["SHA-384"] = "SHA-384",
                ["SHA-512"] = "SHA-512",
            };

        private static readonly Dictionary<String, int>
            MIN_SDK_VESION_FROM_WHICH_DIGEST_SUPPORTED_IN_MANIFEST = new Dictionary<string, int>
            {
                ["MD5"] = 0,
                ["SHA-1"] = 0,
                ["SHA-256"] = 0,
                ["SHA-384"] = AndroidSdkVersion.GINGERBREAD,
                ["SHA-512"] = AndroidSdkVersion.GINGERBREAD,
            };

        private static byte[] getDigest(IEnumerable<NamedDigest> digests, String jcaDigestAlgorithm)
        {
            foreach (NamedDigest digest in digests)
            {
                if (digest.jcaDigestAlgorithm.Equals(jcaDigestAlgorithm, StringComparison.OrdinalIgnoreCase))
                {
                    return digest.digest;
                }
            }

            return null;
        }

        public static List<CentralDirectoryRecord> parseZipCentralDirectory(
            DataSource apk,
            ZipSections apkSections)

        {
            return ZipUtils.parseZipCentralDirectory(apk, apkSections);
        }

        /**
 * Returns {@code true} if the provided JAR entry must be mentioned in signed JAR archive's
 * manifest for the APK to verify on Android.
 */
        private static bool isJarEntryDigestNeededInManifest(String entryName)
        {
            // NOTE: This logic is different from what's required by the JAR signing scheme. This is
            // because Android's APK verification logic differs from that spec. In particular, JAR
            // signing spec includes into JAR manifest all files in subdirectories of META-INF and
            // any files inside META-INF not related to signatures.
            if (entryName.StartsWith("META-INF/"))
            {
                return false;
            }

            return !entryName.EndsWith("/");
        }

        private static ISet<Signer> verifyJarEntriesAgainstManifestAndSigners(
            DataSource apk,
            long cdOffsetInApk,
            IList<CentralDirectoryRecord> cdRecords,
            Dictionary<String, ManifestParser.Section> entryNameToManifestSection,
            List<Signer> signers,
            int minSdkVersion,
            int maxSdkVersion,
            Result result)

        {
            // Iterate over APK contents as sequentially as possible to improve performance.
            List<CentralDirectoryRecord> cdRecordsSortedByLocalFileHeaderOffset =
                new List<CentralDirectoryRecord>(cdRecords);
            cdRecordsSortedByLocalFileHeaderOffset.Sort(CentralDirectoryRecord.BY_LOCAL_FILE_HEADER_OFFSET_COMPARATOR);
            List<Signer> firstSignedEntrySigners = null;
            String firstSignedEntryName = null;
            foreach (CentralDirectoryRecord cdRecord in cdRecordsSortedByLocalFileHeaderOffset)
            {
                String entryName = cdRecord.getName();
                if (!isJarEntryDigestNeededInManifest(entryName))
                {
                    continue;
                }

                entryNameToManifestSection.TryGetValue(entryName, out var manifestSection);
                if (manifestSection == null)
                {
                    result.addError(ApkVerifier.Issue.JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_MANIFEST, entryName);
                    continue;
                }

                List<Signer> entrySigners = new List<Signer>(signers.Count);
                foreach (Signer signer in
                         signers)
                {
                    if (signer.getSigFileEntryNames().Contains(entryName))
                    {
                        entrySigners.Add(signer);
                    }
                }

                if (entrySigners.Count == 0)
                {
                    result.addError(ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_NOT_SIGNED, entryName);
                    continue;
                }

                if (firstSignedEntrySigners == null)
                {
                    firstSignedEntrySigners = entrySigners;
                    firstSignedEntryName = entryName;
                }
                else if (!entrySigners.Equals(firstSignedEntrySigners))
                {
                    result.addError(
                        ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_SIGNERS_MISMATCH,
                        firstSignedEntryName,
                        getSignerNames(firstSignedEntrySigners),
                        entryName,
                        getSignerNames(entrySigners));
                    continue;
                }

                List<NamedDigest> expectedDigests =
                    new List<NamedDigest>(
                        getDigestsToVerify(
                            manifestSection, "-Digest", minSdkVersion, maxSdkVersion));
                if (expectedDigests.Count == 0)
                {
                    result.addError(ApkVerifier.Issue.JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_MANIFEST, entryName);
                    continue;
                }

                HashAlgorithm[] mds = new HashAlgorithm[expectedDigests.Count];
                for (int i = 0; i < expectedDigests.Count; i++)
                {
                    mds[i] = getMessageDigest(expectedDigests[i].jcaDigestAlgorithm);
                }

                try
                {
                    LocalFileRecord.outputUncompressedData(
                        apk,
                        cdRecord,
                        cdOffsetInApk,
                        DataSinks.asDataSink(mds));
                }
                catch (ZipFormatException e)
                {
                    throw new ApkFormatException("Malformed ZIP entry: " + entryName, e);
                }
                catch (IOException e)
                {
                    throw new IOException("Failed to read entry: " + entryName, e);
                }

                for (int i = 0; i < expectedDigests.Count; i++)
                {
                    NamedDigest expectedDigest = expectedDigests[i];
                    mds[i].TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                    byte[] actualDigest = mds[i].Hash;
                    mds[i].Dispose();
                    if (!expectedDigest.digest.SequenceEqual(actualDigest))
                    {
                        result.addError(
                            ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY,
                            entryName,
                            expectedDigest.jcaDigestAlgorithm,
                            V1SchemeConstants.MANIFEST_ENTRY_NAME,
                            Convert.ToBase64String(actualDigest),
                            Convert.ToBase64String(expectedDigest.digest));
                    }
                }
            }

            if (firstSignedEntrySigners == null)
            {
                result.addError(ApkVerifier.Issue.JAR_SIG_NO_SIGNED_ZIP_ENTRIES);
                return new HashSet<Signer>();
            }
            else
            {
                return new HashSet<Signer>(firstSignedEntrySigners);
            }
        }

        private static List<String> getSignerNames(List<Signer> signers)
        {
            if (signers.Count == 0)
            {
                return new List<string>();
            }

            List<String> result = new List<string>(signers.Count);
            foreach (Signer signer in signers)
            {
                result.Add(signer.getName());
            }

            return result;
        }

        private static HashAlgorithm getMessageDigest(String algorithm)
        {
            return HashAlgorithm.Create(algorithm);
        }

        private static byte[] digest(String algorithm, byte[] data, int offset, int length)
        {
            HashAlgorithm md = getMessageDigest(algorithm);
            return md.ComputeHash(data, offset, length);
        }

        private static byte[] digest(String algorithm, byte[] data)
        {
            return getMessageDigest(algorithm).ComputeHash(data);
        }

        public class NamedDigest
        {
            public readonly String jcaDigestAlgorithm;
            public readonly byte[] digest;

            public NamedDigest(String jcaDigestAlgorithm, byte[] digest)
            {
                this.jcaDigestAlgorithm = jcaDigestAlgorithm;
                this.digest = digest;
            }
        }

        public class Result
        {
            /** Whether the APK's JAR signature verifies. */
            public bool verified;

            /** List of APK's signers. These signers are used by Android. */
            public readonly List<SignerInfo> signers = new List<SignerInfo>();

            /**
         * Signers encountered in the APK but not included in the set of the APK's signers. These
         * signers are ignored by Android.
         */
            public readonly List<SignerInfo> ignoredSigners = new List<SignerInfo>();

            private readonly List<ApkVerifier.IssueWithParams> mWarnings = new List<ApkVerifier.IssueWithParams>();
            private readonly List<ApkVerifier.IssueWithParams> mErrors = new List<ApkVerifier.IssueWithParams>();

            public bool containsErrors()
            {
                if (mErrors.Count != 0)
                {
                    return true;
                }

                foreach (SignerInfo signer in signers)
                {
                    if (signer.containsErrors())
                    {
                        return true;
                    }
                }

                return false;
            }

            public void addError(ApkVerifier.Issue msg, params Object[] parameters)
            {
                mErrors.Add(new ApkVerifier.IssueWithParams(msg, parameters));
            }

            public void addWarning(ApkVerifier.Issue msg, params Object[] parameters)
            {
                mWarnings.Add(new ApkVerifier.IssueWithParams(msg, parameters));
            }

            public List<ApkVerifier.IssueWithParams> getErrors()
            {
                return mErrors;
            }

            public List<ApkVerifier.IssueWithParams> getWarnings()
            {
                return mWarnings;
            }

            public class SignerInfo
            {
                public readonly String name;
                public readonly String signatureFileName;
                public readonly String signatureBlockFileName;
                public readonly List<X509Certificate> certChain = new List<X509Certificate>();

                private readonly List<ApkVerifier.IssueWithParams> mWarnings = new List<ApkVerifier.IssueWithParams>();
                private readonly List<ApkVerifier.IssueWithParams> mErrors = new List<ApkVerifier.IssueWithParams>();

                public SignerInfo(
                    String name, String signatureBlockFileName, String signatureFileName)
                {
                    this.name = name;
                    this.signatureBlockFileName = signatureBlockFileName;
                    this.signatureFileName = signatureFileName;
                }

                public bool containsErrors()
                {
                    return mErrors.Count != 0;
                }

                public void addError(ApkVerifier.Issue msg, params Object[] parameters)
                {
                    mErrors.Add(new ApkVerifier.IssueWithParams(msg, parameters));
                }

                public void addWarning(ApkVerifier.Issue msg, params Object[] parameters)
                {
                    mWarnings.Add(new ApkVerifier.IssueWithParams(msg, parameters));
                }

                public List<ApkVerifier.IssueWithParams> getErrors()
                {
                    return mErrors;
                }

                public List<ApkVerifier.IssueWithParams> getWarnings()
                {
                    return mWarnings;
                }
            }
        }

        private class SignedAttributes
        {
            private Dictionary<String, List<Asn1OpaqueObject>> mAttrs;

            public SignedAttributes(IList<Pkcs7.Attribute> attrs)
            {
                Dictionary<String, List<Asn1OpaqueObject>> result =
                    new Dictionary<String, List<Asn1OpaqueObject>>(attrs.Count);
                foreach (Pkcs7.Attribute attr in attrs)
                {
                    if (result.ContainsKey(attr.attrType))
                    {
                        throw new Pkcs7DecodingException("Duplicate signed attribute: " + attr.attrType);
                    }

                    result[attr.attrType] = attr.attrValues;
                }

                mAttrs = result;
            }

            private Asn1OpaqueObject getSingleValue(String attrOid)
            {
                mAttrs.TryGetValue(attrOid, out var values);
                if ((values == null) || (values.Count == 0))
                {
                    return null;
                }

                if (values.Count > 1)
                {
                    throw new Pkcs7DecodingException("Attribute " + attrOid + " has multiple values");
                }

                return values[0];
            }

            public String getSingleObjectIdentifierValue(String attrOid)
            {
                Asn1OpaqueObject value = getSingleValue(attrOid);
                if (value == null)
                {
                    return null;
                }

                try
                {
                    return Asn1BerParser.parse<ObjectIdentifierChoice>(value.getEncoded()).value;
                }
                catch (Asn1DecodingException e)
                {
                    throw new Pkcs7DecodingException("Failed to decode OBJECT IDENTIFIER", e);
                }
            }

            public byte[] getSingleOctetStringValue(String attrOid)
            {
                Asn1OpaqueObject value = getSingleValue(attrOid);
                if (value == null)
                {
                    return null;
                }

                try
                {
                    return Asn1BerParser.parse<OctetStringChoice>(value.getEncoded()).value;
                }
                catch (Asn1DecodingException e)
                {
                    throw new Pkcs7DecodingException("Failed to decode OBJECT IDENTIFIER", e);
                }
            }
        }

        [Asn1Class(Type = Asn1Type.CHOICE)]
        public class OctetStringChoice
        {
            [Asn1Field(Type = Asn1Type.OCTET_STRING)]
            public byte[] value;
        }

        [Asn1Class(Type = Asn1Type.CHOICE)]
        public class ObjectIdentifierChoice
        {
            [Asn1Field(Type = Asn1Type.OBJECT_IDENTIFIER)]
            public String value;
        }
    }
}