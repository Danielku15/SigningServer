/*
 * Copyright (C) 2020 The Android Open Source Project
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
using SigningServer.Android;
using SigningServer.Android.ApkSig;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.Stamp;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Android.ApkSig.Internal.Apk.v2;
using SigningServer.Android.ApkSig.Internal.Apk.v3;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Internal.X509;
using SigningServer.Android.ApkSig.Internal.Zip;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;
using SourceStampVerifier = SigningServer.Android.ApkSig.Internal.Apk.Stamp.SourceStampVerifier;

namespace SigningServer.Android.ApkSig
{
    /**
     * APK source stamp verifier intended only to verify the validity of the stamp signature.
     *
     * <p>Note, this verifier does not validate the signatures of the jar signing / APK signature blocks
     * when obtaining the digests for verification. This verifier should only be used in cases where
     * another mechanism has already been used to verify the APK signatures.
     */
    public class SourceStampVerifier
    {
        private readonly FileInfo mApkFile;
        private readonly DataSource mApkDataSource;

        private readonly int mMinSdkVersion;
        private readonly int mMaxSdkVersion;

        private SourceStampVerifier(
            FileInfo apkFile,
            DataSource apkDataSource,
            int minSdkVersion,
            int maxSdkVersion)
        {
            mApkFile = apkFile;
            mApkDataSource = apkDataSource;
            mMinSdkVersion = minSdkVersion;
            mMaxSdkVersion = maxSdkVersion;
        }

        /**
     * Verifies the APK's source stamp signature and returns the result of the verification.
     *
     * <p>The APK's source stamp can be considered verified if the result's {@link
     * Result#isVerified()} returns {@code true}. If source stamp verification fails all of the
     * resulting errors can be obtained from {@link Result#getAllErrors()}, or individual errors
     * can be obtained as follows:
     * <ul>
     *     <li>Obtain the generic errors via {@link Result#getErrors()}
     *     <li>Obtain the V2 signers via {@link Result#getV2SchemeSigners()}, then for each signer
     *     query for any errors with {@link Result.SignerInfo#getErrors()}
     *     <li>Obtain the V3 signers via {@link Result#getV3SchemeSigners()}, then for each signer
     *     query for any errors with {@link Result.SignerInfo#getErrors()}
     *     <li>Obtain the source stamp signer via {@link Result#getSourceStampInfo()}, then query
     *     for any stamp errors with {@link Result.SourceStampInfo#getErrors()}
     * </ul>
     */
        public SourceStampVerifier.Result verifySourceStamp()
        {
            return verifySourceStamp(null);
        }

        /**
     * Verifies the APK's source stamp signature, including verification that the SHA-256 digest of
     * the stamp signing certificate matches the {@code expectedCertDigest}, and returns the result
     * of the verification.
     *
     * <p>A value of {@code null} for the {@code expectedCertDigest} will verify the source stamp,
     * if present, without verifying the actual source stamp certificate used to sign the source
     * stamp. This can be used to verify an APK contains a properly signed source stamp without
     * verifying a particular signer.
     *
     * @see #verifySourceStamp()
     */
        public SourceStampVerifier.Result verifySourceStamp(String expectedCertDigest)
        {
            IDisposable @in = null;
            try
            {
                DataSource apk;
                if (mApkDataSource != null)
                {
                    apk = mApkDataSource;
                }
                else if (mApkFile != null)
                {
                    RandomAccessFile f = new RandomAccessFile(mApkFile, "r");
                    @in = f;
                    apk = DataSources.asDataSource(f, 0, f.length());
                }
                else
                {
                    throw new InvalidOperationException("APK not provided");
                }

                return verifySourceStamp(apk, expectedCertDigest);
            }
            catch (IOException e)
            {
                Result result = new Result();
                result.addVerificationError(ApkVerificationIssue.UNEXPECTED_EXCEPTION, e);
                return result;
            }
            finally
            {
                if (@in != null)
                {
                    try
                    {
                        @in.Dispose();
                    }
                    catch (IOException ignored)
                    {
                    }
                }
            }
        }

        /**
     * Verifies the provided {@code apk}'s source stamp signature, including verification of the
     * SHA-256 digest of the stamp signing certificate matches the {@code expectedCertDigest}, and
     * returns the result of the verification.
     *
     * @see #verifySourceStamp(String)
     */
        private SourceStampVerifier.Result verifySourceStamp(DataSource apk,
            String expectedCertDigest)
        {
            Result result = new Result();
            try
            {
                ZipSections zipSections = ApkUtilsLite.findZipSections(apk);
                // Attempt to obtain the source stamp's certificate digest from the APK.
                List<CentralDirectoryRecord> cdRecords =
                    ZipUtils.parseZipCentralDirectory(apk, zipSections);
                CentralDirectoryRecord sourceStampCdRecord = null;
                foreach (CentralDirectoryRecord cdRecord in
                         cdRecords)
                {
                    if (ApkUtils.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME.Equals(cdRecord.getName()))
                    {
                        sourceStampCdRecord = cdRecord;
                        break;
                    }
                }

                // If the source stamp's certificate digest is not available within the APK then the
                // source stamp cannot be verified; check if a source stamp signing block is in the
                // APK's signature block to determine the appropriate status to return.
                if (sourceStampCdRecord == null)
                {
                    bool stampSigningBlockFound;
                    try
                    {
                        ApkSigningBlockUtilsLite.findSignature(apk, zipSections,
                            SourceStampConstants.V2_SOURCE_STAMP_BLOCK_ID);
                        stampSigningBlockFound = true;
                    }
                    catch (SignatureNotFoundException e)
                    {
                        stampSigningBlockFound = false;
                    }

                    result.addVerificationError(stampSigningBlockFound
                        ? ApkVerificationIssue.SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST
                        : ApkVerificationIssue.SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING);
                    return result;
                }

                // Verify that the contents of the source stamp certificate digest match the expected
                // value, if provided.
                byte[] sourceStampCertificateDigest =
                    LocalFileRecord.getUncompressedData(
                        apk,
                        sourceStampCdRecord,
                        zipSections.getZipCentralDirectoryOffset());
                if (expectedCertDigest != null)
                {
                    String actualCertDigest = ApkSigningBlockUtilsLite.toHex(
                        sourceStampCertificateDigest);
                    if (!expectedCertDigest.Equals(actualCertDigest, StringComparison.OrdinalIgnoreCase))
                    {
                        result.addVerificationError(
                            ApkVerificationIssue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH,
                            actualCertDigest, expectedCertDigest);
                        return result;
                    }
                }

                Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests =
                    new Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>>();
                if (mMaxSdkVersion >= AndroidSdkVersion.P)
                {
                    SignatureInfo signatureInfo;
                    try
                    {
                        signatureInfo = ApkSigningBlockUtilsLite.findSignature(apk, zipSections,
                            V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID);
                    }
                    catch (SignatureNotFoundException e)
                    {
                        signatureInfo = null;
                    }

                    if (signatureInfo != null)
                    {
                        Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests =
                            new Dictionary<ContentDigestAlgorithm, byte[]>();
                        parseSigners(signatureInfo.signatureBlock, ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3,
                            apkContentDigests, result);
                        signatureSchemeApkContentDigests.Add(
                            ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3, apkContentDigests);
                    }
                }

                if (mMaxSdkVersion >= AndroidSdkVersion.N && (mMinSdkVersion < AndroidSdkVersion.P ||
                                                              signatureSchemeApkContentDigests.Count == 0))
                {
                    SignatureInfo signatureInfo;
                    try
                    {
                        signatureInfo = ApkSigningBlockUtilsLite.findSignature(apk, zipSections,
                            V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID);
                    }
                    catch (SignatureNotFoundException e)
                    {
                        signatureInfo = null;
                    }

                    if (signatureInfo != null)
                    {
                        Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests =
                            new Dictionary<ContentDigestAlgorithm, byte[]>();
                        parseSigners(signatureInfo.signatureBlock, ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2,
                            apkContentDigests, result);
                        signatureSchemeApkContentDigests.Add(
                            ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2, apkContentDigests);
                    }
                }

                if (mMinSdkVersion < AndroidSdkVersion.N
                    || signatureSchemeApkContentDigests.Count == 0)
                {
                    Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests =
                        getApkContentDigestFromV1SigningScheme(cdRecords, apk, zipSections, result);
                    signatureSchemeApkContentDigests.Add(ApkSigningBlockUtils.VERSION_JAR_SIGNATURE_SCHEME,
                        apkContentDigests);
                }

                ApkSigResult sourceStampResult =
                    V2SourceStampVerifier.verify(
                        apk,
                        zipSections,
                        sourceStampCertificateDigest,
                        signatureSchemeApkContentDigests,
                        mMinSdkVersion,
                        mMaxSdkVersion);
                result.mergeFrom(sourceStampResult);
                return result;
            }
            catch (Exception e) when (e is ApkFormatException || e is IOException || e is ZipFormatException)
            {
                result.addVerificationError(ApkVerificationIssue.MALFORMED_APK, e);
            }
            catch (CryptographicException e)
            {
                result.addVerificationError(ApkVerificationIssue.UNEXPECTED_EXCEPTION, e);
            }
            catch (SignatureNotFoundException e)
            {
                result.addVerificationError(ApkVerificationIssue.SOURCE_STAMP_SIG_MISSING);
            }

            return result;
        }

        /**
     * Parses each signer in the provided APK V2 / V3 signature block and populates corresponding
     * {@code SignerInfo} of the provided {@code result} and their {@code apkContentDigests}.
     *
     * <p>This method adds one or more errors to the {@code result} if a verification error is
     * expected to be encountered on an Android platform version in the
     * {@code [minSdkVersion, maxSdkVersion]} range.
     */
        public static void parseSigners(
            ByteBuffer apkSignatureSchemeBlock,
            int apkSigSchemeVersion,
            Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests,
            Result result)
        {
            bool isV2Block = apkSigSchemeVersion == ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2;
            // Both the V2 and V3 signature blocks contain the following:
            // * length-prefixed sequence of length-prefixed signers
            ByteBuffer signers;
            try
            {
                signers = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(apkSignatureSchemeBlock);
            }
            catch (ApkFormatException e)
            {
                result.addVerificationWarning(isV2Block
                    ? ApkVerificationIssue.V2_SIG_MALFORMED_SIGNERS
                    : ApkVerificationIssue.V3_SIG_MALFORMED_SIGNERS);
                return;
            }

            if (!signers.hasRemaining())
            {
                result.addVerificationWarning(isV2Block
                    ? ApkVerificationIssue.V2_SIG_NO_SIGNERS
                    : ApkVerificationIssue.V3_SIG_NO_SIGNERS);
                return;
            }

            while (signers.hasRemaining())
            {
                Result.SignerInfo signerInfo = new Result.SignerInfo();
                if (isV2Block)
                {
                    result.addV2Signer(signerInfo);
                }
                else
                {
                    result.addV3Signer(signerInfo);
                }

                try
                {
                    ByteBuffer signer = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(signers);
                    parseSigner(
                        signer,
                        apkSigSchemeVersion,
                        apkContentDigests,
                        signerInfo);
                }
                catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
                {
                    signerInfo.addVerificationWarning(
                        isV2Block
                            ? ApkVerificationIssue.V2_SIG_MALFORMED_SIGNER
                            : ApkVerificationIssue.V3_SIG_MALFORMED_SIGNER);
                    return;
                }
            }
        }

        /**
     * Parses the provided signer block and populates the {@code result}.
     *
     * <p>This verifies signatures over {@code signed-data} contained in this block but does not
     * verify the integrity of the rest of the APK. To facilitate APK integrity verification, this
     * method adds the {@code contentDigestsToVerify}. These digests can then be used to verify the
     * integrity of the APK.
     *
     * <p>This method adds one or more errors to the {@code result} if a verification error is
     * expected to be encountered on an Android platform version in the
     * {@code [minSdkVersion, maxSdkVersion]} range.
     */
        private static void parseSigner(
            ByteBuffer signerBlock,
            int apkSigSchemeVersion,
            Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests,
            Result.SignerInfo signerInfo)

        {
            bool isV2Signer = apkSigSchemeVersion == ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2;
            // Both the V2 and V3 signer blocks contain the following:
            // * length-prefixed signed data
            //   * length-prefixed sequence of length-prefixed digests:
            //     * uint32: signature algorithm ID
            //     * length-prefixed bytes: digest of contents
            //   * length-prefixed sequence of certificates:
            //     * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
            ByteBuffer signedData = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(signerBlock);
            ByteBuffer digests = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(signedData);

            ByteBuffer certificates = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(signedData);

            // Parse the digests block
            while (digests.hasRemaining())
            {
                try
                {
                    ByteBuffer digest = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(digests);
                    int sigAlgorithmId = digest.getInt();
                    byte[] digestBytes = ApkSigningBlockUtilsLite.readLengthPrefixedByteArray(digest);
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(sigAlgorithmId);
                    if (signatureAlgorithm == null)
                    {
                        continue;
                    }

                    apkContentDigests.Add(signatureAlgorithm.getContentDigestAlgorithm(), digestBytes);
                }
                catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
                {
                    signerInfo.addVerificationWarning(
                        isV2Signer
                            ? ApkVerificationIssue.V2_SIG_MALFORMED_DIGEST
                            : ApkVerificationIssue.V3_SIG_MALFORMED_DIGEST);
                    return;
                }
            }

            // Parse the certificates block
            if (certificates.hasRemaining())
            {
                byte[] encodedCert = ApkSigningBlockUtilsLite.readLengthPrefixedByteArray(certificates);
                X509Certificate certificate;
                try
                {
                    certificate = new WrappedX509Certificate(encodedCert);
                }
                catch (CryptographicException e)
                {
                    signerInfo.addVerificationWarning(
                        isV2Signer
                            ? ApkVerificationIssue.V2_SIG_MALFORMED_CERTIFICATE
                            : ApkVerificationIssue.V3_SIG_MALFORMED_CERTIFICATE);
                    return;
                }

                // Wrap the cert so that the result's getEncoded returns exactly the original encoded
                // form. Without this, getEncoded may return a different form from what was stored in
                // the signature. This is because some X509Certificate(Factory) implementations
                // re-encode certificates.
                certificate = new GuaranteedEncodedFormX509Certificate(certificate, encodedCert);
                signerInfo.setSigningCertificate(certificate);
            }

            if (signerInfo.getSigningCertificate() == null)
            {
                signerInfo.addVerificationWarning(
                    isV2Signer
                        ? ApkVerificationIssue.V2_SIG_NO_CERTIFICATES
                        : ApkVerificationIssue.V3_SIG_NO_CERTIFICATES);
                return;
            }
        }

        /**
 * Returns a mapping of the {@link ContentDigestAlgorithm} to the {@code byte[]} digest of the
 * V1 / jar signing META-INF/MANIFEST.MF; if this file is not found then an empty {@code Map} is
 * returned.
 *
 * <p>If any errors are encountered while parsing the V1 signers the provided {@code result}
 * will be updated to include a warning, but the source stamp verification can still proceed.
 */
        private static Dictionary<ContentDigestAlgorithm, byte[]> getApkContentDigestFromV1SigningScheme(
            List<CentralDirectoryRecord> cdRecords,
            DataSource apk,
            ZipSections zipSections,
            Result result)

        {
            CentralDirectoryRecord manifestCdRecord = null;
            List<CentralDirectoryRecord> signatureBlockRecords = new List<CentralDirectoryRecord>(1);
            Dictionary<ContentDigestAlgorithm, byte[]> v1ContentDigest =
                new Dictionary<ContentDigestAlgorithm, byte[]>();
            foreach (CentralDirectoryRecord cdRecord in cdRecords)
            {
                String cdRecordName = cdRecord.getName();
                if (cdRecordName == null)
                {
                    continue;
                }

                if (manifestCdRecord == null && V1SchemeConstants.MANIFEST_ENTRY_NAME.Equals(cdRecordName))
                {
                    manifestCdRecord = cdRecord;
                    continue;
                }

                if (cdRecordName.StartsWith("META-INF/")
                    && (cdRecordName.EndsWith(".RSA")
                        || cdRecordName.EndsWith(".DSA")
                        || cdRecordName.EndsWith(".EC")))
                {
                    signatureBlockRecords.Add(cdRecord);
                }
            }

            if (manifestCdRecord == null)
            {
                // No JAR signing manifest file found. For SourceStamp verification, returning an empty
                // digest is enough since this would affect the readonly digest signed by the stamp, and
                // thus an empty digest will invalidate that signature.
                return v1ContentDigest;
            }

            if (signatureBlockRecords.Count == 0)
            {
                result.addVerificationWarning(ApkVerificationIssue.JAR_SIG_NO_SIGNATURES);
            }
            else
            {
                foreach (CentralDirectoryRecord signatureBlockRecord in signatureBlockRecords)
                {
                    try
                    {
                        byte[] signatureBlockBytes = LocalFileRecord.getUncompressedData(apk,
                            signatureBlockRecord, zipSections.getZipCentralDirectoryOffset());
                        foreach (var certificate in X509CertificateUtils.generateCertificates(new MemoryStream(signatureBlockBytes)))
                        {
                            // If multiple certificates are found within the signature block only the
                            // first is used as the signer of this block.
                            Result.SignerInfo signerInfo = new Result.SignerInfo();
                            signerInfo.setSigningCertificate((X509Certificate)certificate);
                            result.addV1Signer(signerInfo);
                            break;
                        }
                    }
                    catch (CryptographicException e)
                    {
                        // Log a warning for the parsing exception but still proceed with the stamp
                        // verification.
                        result.addVerificationWarning(ApkVerificationIssue.JAR_SIG_PARSE_EXCEPTION,
                            signatureBlockRecord.getName(), e);
                        break;
                    }
                    catch (ZipFormatException e)
                    {
                        throw new ApkFormatException("Failed to read APK", e);
                    }
                }
            }

            try
            {
                byte[] manifestBytes =
                    LocalFileRecord.getUncompressedData(
                        apk, manifestCdRecord, zipSections.getZipCentralDirectoryOffset());
                v1ContentDigest.Add(
                    ContentDigestAlgorithm.SHA256, ApkUtils.computeSha256DigestBytes(manifestBytes));
                return v1ContentDigest;
            }
            catch (ZipFormatException e)
            {
                throw new ApkFormatException("Failed to read APK", e);
            }
        }

        /**
     * Result of verifying the APK's source stamp signature; this signature can only be considered
     * verified if {@link #isVerified()} returns true.
     */
        public class Result
        {
            private readonly List<SignerInfo> mV1SchemeSigners = new List<SignerInfo>();
            private readonly List<SignerInfo> mV2SchemeSigners = new List<SignerInfo>();
            private readonly List<SignerInfo> mV3SchemeSigners = new List<SignerInfo>();

            private readonly List<List<SignerInfo>> mAllSchemeSigners;

            private SourceStampInfo mSourceStampInfo;

            private readonly List<ApkVerificationIssue> mErrors = new List<ApkVerificationIssue>();
            private readonly List<ApkVerificationIssue> mWarnings = new List<ApkVerificationIssue>();

            private bool mVerified;

            public Result()
            {
                mAllSchemeSigners = new List<List<SignerInfo>>
                {
                    mV1SchemeSigners,
                    mV2SchemeSigners,
                    mV3SchemeSigners
                };
            }

            public void addVerificationError(int errorId, params Object[] parameters)
            {
                mErrors.Add(new ApkVerificationIssue(errorId, parameters));
            }

            public void addVerificationWarning(int warningId, params Object[] parameters)
            {
                mWarnings.Add(new ApkVerificationIssue(warningId, parameters));
            }

            public void addV1Signer(SignerInfo signerInfo)
            {
                mV1SchemeSigners.Add(signerInfo);
            }

            public void addV2Signer(SignerInfo signerInfo)
            {
                mV2SchemeSigners.Add(signerInfo);
            }

            public void addV3Signer(SignerInfo signerInfo)
            {
                mV3SchemeSigners.Add(signerInfo);
            }

            /**
         * Returns {@code true} if the APK's source stamp signature
         */
            public bool isVerified()
            {
                return mVerified;
            }

            public void mergeFrom(ApkSigResult source)
            {
                switch (source.signatureSchemeVersion)
                {
                    case Constants.VERSION_SOURCE_STAMP:
                        mVerified = source.verified;
                        if (source.mSigners.Count != 0)
                        {
                            mSourceStampInfo = new SourceStampInfo(source.mSigners[0]);
                        }

                        break;
                    default:
                        throw new ArgumentException(
                            "Unknown ApkSigResult Signing Block Scheme Id "
                            + source.signatureSchemeVersion);
                }
            }

            /**
         * Returns a {@code List} of {@link SignerInfo} objects representing the V1 signers of the
         * provided APK.
         */
            public List<SignerInfo> getV1SchemeSigners()
            {
                return mV1SchemeSigners;
            }

            /**
         * Returns a {@code List} of {@link SignerInfo} objects representing the V2 signers of the
         * provided APK.
         */
            public List<SignerInfo> getV2SchemeSigners()
            {
                return mV2SchemeSigners;
            }

            /**
         * Returns a {@code List} of {@link SignerInfo} objects representing the V3 signers of the
         * provided APK.
         */
            public List<SignerInfo> getV3SchemeSigners()
            {
                return mV3SchemeSigners;
            }

            /**
         * Returns the {@link SourceStampInfo} instance representing the source stamp signer for the
         * APK, or null if the source stamp signature verification failed before the stamp signature
         * block could be fully parsed.
         */
            public SourceStampInfo getSourceStampInfo()
            {
                return mSourceStampInfo;
            }

            /**
         * Returns {@code true} if an error was encountered while verifying the APK.
         *
         * <p>Any error prevents the APK from being considered verified.
         */
            public bool containsErrors()
            {
                if (mErrors.Count != 0)
                {
                    return true;
                }

                foreach (System.Collections.Generic.List<SignerInfo> signers in mAllSchemeSigners)
                {
                    foreach (SignerInfo signer in signers)
                    {
                        if (signer.containsErrors())
                        {
                            return true;
                        }
                    }
                }

                if (mSourceStampInfo != null)
                {
                    if (mSourceStampInfo.containsErrors())
                    {
                        return true;
                    }
                }

                return false;
            }

            /**
         * Returns the errors encountered while verifying the APK's source stamp.
         */
            public List<ApkVerificationIssue> getErrors()
            {
                return mErrors;
            }

            /**
         * Returns the warnings encountered while verifying the APK's source stamp.
         */
            public List<ApkVerificationIssue> getWarnings()
            {
                return mWarnings;
            }

            /**
         * Returns all errors for this result, including any errors from signature scheme signers
         * and the source stamp.
         */
            public List<ApkVerificationIssue> getAllErrors()
            {
                List<ApkVerificationIssue> errors = new List<ApkVerificationIssue>();
                errors.AddRange(mErrors);

                foreach (System.Collections.Generic.List<SignerInfo> signers in mAllSchemeSigners)
                {
                    foreach (SignerInfo signer in signers)
                    {
                        errors.AddRange(signer.getErrors());
                    }
                }

                if (mSourceStampInfo != null)
                {
                    errors.AddRange(mSourceStampInfo.getErrors());
                }

                return errors;
            }

            /**
         * Returns all warnings for this result, including any warnings from signature scheme
         * signers and the source stamp.
         */
            public List<ApkVerificationIssue> getAllWarnings()
            {
                List<ApkVerificationIssue> warnings = new List<ApkVerificationIssue>();
                warnings.AddRange(mWarnings);

                foreach (System.Collections.Generic.List<SignerInfo> signers in
                         mAllSchemeSigners)
                {
                    foreach (SignerInfo signer in signers)
                    {
                        warnings.AddRange(signer.getWarnings());
                    }
                }

                if (mSourceStampInfo != null)
                {
                    warnings.AddRange(mSourceStampInfo.getWarnings());
                }

                return warnings;
            }

            /**
         * Contains information about an APK's signer and any errors encountered while parsing the
         * corresponding signature block.
         */
            public class SignerInfo
            {
                private X509Certificate mSigningCertificate;
                private readonly List<ApkVerificationIssue> mErrors = new List<ApkVerificationIssue>();
                private readonly List<ApkVerificationIssue> mWarnings = new List<ApkVerificationIssue>();

                public void setSigningCertificate(X509Certificate signingCertificate)
                {
                    mSigningCertificate = signingCertificate;
                }

                void addVerificationError(int errorId, params Object[] parameters)
                {
                    mErrors.Add(new ApkVerificationIssue(errorId, parameters));
                }

                public void addVerificationWarning(int warningId, params Object[] parameters)
                {
                    mWarnings.Add(new ApkVerificationIssue(warningId, parameters));
                }

                /**
             * Returns the current signing certificate used by this signer.
             */
                public X509Certificate getSigningCertificate()
                {
                    return mSigningCertificate;
                }

                /**
             * Returns a {@link List} of {@link ApkVerificationIssue} objects representing errors
             * encountered during processing of this signer's signature block.
             */
                public List<ApkVerificationIssue> getErrors()
                {
                    return mErrors;
                }

                /**
             * Returns a {@link List} of {@link ApkVerificationIssue} objects representing warnings
             * encountered during processing of this signer's signature block.
             */
                public List<ApkVerificationIssue> getWarnings()
                {
                    return mWarnings;
                }

                /**
             * Returns {@code true} if any errors were encountered while parsing this signer's
             * signature block.
             */
                public bool containsErrors()
                {
                    return mErrors.Count != 0;
                }
            }

            /**
         * Contains information about an APK's source stamp and any errors encountered while
         * parsing the stamp signature block.
         */
            public class SourceStampInfo
            {
                private readonly List<X509Certificate> mCertificates;
                private readonly List<X509Certificate> mCertificateLineage;

                private readonly List<ApkVerificationIssue> mErrors = new List<ApkVerificationIssue>();
                private readonly List<ApkVerificationIssue> mWarnings = new List<ApkVerificationIssue>();

                /*
                 * Since this utility is intended just to verify the source stamp, and the source stamp
                 * currently only logs warnings to prevent failing the APK signature verification, treat
                 * all warnings as errors. If the stamp verification is updated to log errors this
                 * should be set to false to ensure only errors trigger a failure verifying the source
                 * stamp.
                 */
                private static readonly bool mWarningsAsErrors = true;

                public SourceStampInfo(ApkSignerInfo result)
                {
                    mCertificates = result.certs;
                    mCertificateLineage = result.certificateLineage;
                    mErrors.AddRange(result.getErrors());
                    mWarnings.AddRange(result.getWarnings());
                }

                /**
             * Returns the SourceStamp's signing certificate or {@code null} if not available. The
             * certificate is guaranteed to be available if no errors were encountered during
             * verification (see {@link #containsErrors()}.
             *
             * <p>This certificate contains the SourceStamp's public key.
             */
                public X509Certificate getCertificate()
                {
                    return mCertificates.Count == 0 ? null : mCertificates[0];
                }

                /**
             * Returns a {@code List} of {@link X509Certificate} instances representing the source
             * stamp signer's lineage with the oldest signer at element 0, or an empty {@code List}
             * if the stamp's signing certificate has not been rotated.
             */
                public List<X509Certificate> getCertificatesInLineage()
                {
                    return mCertificateLineage;
                }

                /**
             * Returns whether any errors were encountered during the source stamp verification.
             */
                public bool containsErrors()
                {
                    return mErrors.Count != 0 || (mWarningsAsErrors && mWarnings.Count != 0);
                }

                /**
             * Returns a {@code List} of {@link ApkVerificationIssue} representing errors that were
             * encountered during source stamp verification.
             */
                public List<ApkVerificationIssue> getErrors()
                {
                    if (!mWarningsAsErrors)
                    {
                        return mErrors;
                    }

                    List<ApkVerificationIssue> result = new List<ApkVerificationIssue>();
                    result.AddRange(mErrors);
                    result.AddRange(mWarnings);
                    return result;
                }

                /**
             * Returns a {@code List} of {@link ApkVerificationIssue} representing warnings that
             * were encountered during source stamp verification.
             */
                public List<ApkVerificationIssue> getWarnings()
                {
                    return mWarnings;
                }
            }
        }

        /**
     * Builder of {@link SourceStampVerifier} instances.
     *
     * <p> The resulting verifier, by default, checks whether the APK's source stamp signature will
     * verify on all platform versions. The APK's {@code android:minSdkVersion} attribute is not
     * queried to determine the APK's minimum supported level, so the caller should specify a lower
     * bound with {@link #setMinCheckedPlatformVersion(int)}.
     */
        public class Builder
        {
            private readonly FileInfo mApkFile;
            private readonly DataSource mApkDataSource;

            private int mMinSdkVersion = 1;
            private int mMaxSdkVersion = int.MaxValue;

            /**
         * Constructs a new {@code Builder} for source stamp verification of the provided {@code
         * apk}.
         */
            public Builder(FileInfo apk)
            {
                if (apk == null)
                {
                    throw new ArgumentNullException(nameof(apk));
                }

                mApkFile = apk;
                mApkDataSource = null;
            }

            /**
         * Constructs a new {@code Builder} for source stamp verification of the provided {@code
         * apk}.
         */
            public Builder(DataSource apk)
            {
                if (apk == null)
                {
                    throw new ArgumentNullException(nameof(apk));
                }

                mApkDataSource = apk;
                mApkFile = null;
            }

            /**
         * Sets the oldest Android platform version for which the APK's source stamp is verified.
         *
         * <p>APK source stamp verification will confirm that the APK's stamp is expected to verify
         * on all Android platforms starting from the platform version with the provided {@code
         * minSdkVersion}. The upper end of the platform versions range can be modified via
         * {@link #setMaxCheckedPlatformVersion(int)}.
         *
         * @param minSdkVersion API Level of the oldest platform for which to verify the APK
         */
            public SourceStampVerifier.Builder setMinCheckedPlatformVersion(int minSdkVersion)
            {
                mMinSdkVersion = minSdkVersion;
                return this;
            }

            /**
         * Sets the newest Android platform version for which the APK's source stamp  is verified.
         *
         * <p>APK source stamp verification will confirm that the APK's stamp is expected to verify
         * on all platform versions up to and including the proviced {@code maxSdkVersion}. The
         * lower end of the platform versions range can be modified via {@link
         * #setMinCheckedPlatformVersion(int)}.
         *
         * @param maxSdkVersion API Level of the newest platform for which to verify the APK
         * @see #setMinCheckedPlatformVersion(int)
         */
            public SourceStampVerifier.Builder setMaxCheckedPlatformVersion(int maxSdkVersion)
            {
                mMaxSdkVersion = maxSdkVersion;
                return this;
            }

            /**
         * Returns a {@link SourceStampVerifier} initialized according to the configuration of this
         * builder.
         */
            public SourceStampVerifier build()
            {
                return new SourceStampVerifier(
                    mApkFile,
                    mApkDataSource,
                    mMinSdkVersion,
                    mMaxSdkVersion);
            }
        }
    }
}