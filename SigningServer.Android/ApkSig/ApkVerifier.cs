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
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.Stamp;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Android.ApkSig.Internal.Apk.v2;
using SigningServer.Android.ApkSig.Internal.Apk.v3;
using SigningServer.Android.ApkSig.Internal.Apk.v4;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Internal.Zip;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;

namespace SigningServer.Android.ApkSig
{
    /**
     * APK signature verifier which mimics the behavior of the Android platform.
     *
     * <p>The verifier is designed to closely mimic the behavior of Android platforms. This is to enable
     * the verifier to be used for checking whether an APK's signatures are expected to verify on
     * Android.
     *
     * <p>Use {@link Builder} to obtain instances of this verifier.
     *
     * @see <a href="https://source.android.com/security/apksigning/index.html">Application Signing</a>
     */
    public class ApkVerifier
    {
        private static readonly Dictionary<int, String> SUPPORTED_APK_SIG_SCHEME_NAMES =
            loadSupportedApkSigSchemeNames();

        private static Dictionary<int, String> loadSupportedApkSigSchemeNames()
        {
            Dictionary<int, String> supportedMap = new Dictionary<int, string>(2);
            supportedMap.Add(
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2, "APK Signature Scheme v2");
            supportedMap.Add(
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3, "APK Signature Scheme v3");
            return supportedMap;
        }

        private readonly FileInfo mApkFile;
        private readonly DataSource mApkDataSource;
        private readonly FileInfo mV4SignatureFile;

        private readonly int? mMinSdkVersion;
        private readonly int mMaxSdkVersion;

        private ApkVerifier(
            FileInfo apkFile,
            DataSource apkDataSource,
            FileInfo v4SignatureFile,
            int? minSdkVersion,
            int maxSdkVersion)
        {
            mApkFile = apkFile;
            mApkDataSource = apkDataSource;
            mV4SignatureFile = v4SignatureFile;
            mMinSdkVersion = minSdkVersion;
            mMaxSdkVersion = maxSdkVersion;
        }

        /**
     * Verifies the APK's signatures and returns the result of verification. The APK can be
     * considered verified iff the result's {@link Result#isVerified()} returns {@code true}.
     * The verification result also includes errors, warnings, and information about signers such
     * as their signing certificates.
     *
     * <p>Verification succeeds iff the APK's signature is expected to verify on all Android
     * platform versions specified via the {@link Builder}. If the APK's signature is expected to
     * not verify on any of the specified platform versions, this method returns a result with one
     * or more errors and whose {@link Result#isVerified()} returns {@code false}, or this method
     * throws an exception.
     *
     * @throws IOException              if an I/O error is encountered while reading the APK
     * @throws ApkFormatException       if the APK is malformed
     * @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
     *                                  required cryptographic algorithm implementation is missing
     * @throws InvalidOperationException    if this verifier's configuration is missing required
     *                                  information.
     */
        public Result verify()
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

                return verify(apk);
            }
            finally
            {
                if (@in != null)
                {
                    @in.Dispose();
                }
            }
        }

        /**
     * Verifies the APK's signatures and returns the result of verification. The APK can be
     * considered verified iff the result's {@link Result#isVerified()} returns {@code true}.
     * The verification result also includes errors, warnings, and information about signers.
     *
     * @param apk APK file contents
     * @throws IOException              if an I/O error is encountered while reading the APK
     * @throws ApkFormatException       if the APK is malformed
     * @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
     *                                  required cryptographic algorithm implementation is missing
     */
        private Result verify(DataSource apk)
        {
            int maxSdkVersion = mMaxSdkVersion;

            ZipSections zipSections;
            try
            {
                zipSections = ApkUtils.findZipSections(apk);
            }
            catch (ZipFormatException e)
            {
                throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
            }

            ByteBuffer androidManifest = null;

            int? minSdkVersion = verifyAndGetMinSdkVersion(apk, zipSections);

            Result result = new Result();
            Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests =
                new Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>>();

            // The SUPPORTED_APK_SIG_SCHEME_NAMES contains the mapping from version number to scheme
            // name, but the verifiers use this parameter as the schemes supported by the target SDK
            // range. Since the code below skips signature verification based on max SDK the mapping of
            // supported schemes needs to be modified to ensure the verifiers do not report a stripped
            // signature for an SDK range that does not support that signature version. For instance an
            // APK with V1, V2, and V3 signatures and a max SDK of O would skip the V3 signature
            // verification, but the SUPPORTED_APK_SIG_SCHEME_NAMES contains version 3, so when the V2
            // verification is performed it would see the stripping protection attribute, see that V3
            // is in the list of supported signatures, and report a stripped signature.
            Dictionary<int, String> supportedSchemeNames = getSupportedSchemeNames(maxSdkVersion);

            // Android N and newer attempts to verify APKs using the APK Signing Block, which can
            // include v2 and/or v3 signatures.  If none is found, it falls back to JAR signature
            // verification. If the signature is found but does not verify, the APK is rejected.
            ISet<int> foundApkSigSchemeIds = new HashSet<int>(2);
            if (maxSdkVersion >= AndroidSdkVersion.N)
            {
                RunnablesExecutor executor = RunnablesExecutors.SINGLE_THREADED;
                // Android P and newer attempts to verify APKs using APK Signature Scheme v3
                if (maxSdkVersion >= AndroidSdkVersion.P)
                {
                    try
                    {
                        ApkSigningBlockUtils.Result v3Result =
                            V3SchemeVerifier.verify(
                                executor,
                                apk,
                                zipSections,
                                Math.Max(minSdkVersion.GetValueOrDefault(), AndroidSdkVersion.P),
                                maxSdkVersion);
                        foundApkSigSchemeIds.Add(ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
                        result.mergeFrom(v3Result);
                        signatureSchemeApkContentDigests.Add(
                            ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3,
                            getApkContentDigestsFromSigningSchemeResult(v3Result));
                    }
                    catch (ApkSigningBlockUtils.SignatureNotFoundException ignored)
                    {
                        // v3 signature not required
                    }

                    if (result.containsErrors())
                    {
                        return result;
                    }
                }

                // Attempt to verify the APK using v2 signing if necessary. Platforms prior to Android P
                // ignore APK Signature Scheme v3 signatures and always attempt to verify either JAR or
                // APK Signature Scheme v2 signatures.  Android P onwards verifies v2 signatures only if
                // no APK Signature Scheme v3 (or newer scheme) signatures were found.
                if (minSdkVersion < AndroidSdkVersion.P || foundApkSigSchemeIds.Count == 0)
                {
                    try
                    {
                        ApkSigningBlockUtils.Result v2Result =
                            V2SchemeVerifier.verify(
                                executor,
                                apk,
                                zipSections,
                                supportedSchemeNames,
                                foundApkSigSchemeIds,
                                Math.Max(minSdkVersion.GetValueOrDefault(), AndroidSdkVersion.N),
                                maxSdkVersion);
                        foundApkSigSchemeIds.Add(ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2);
                        result.mergeFrom(v2Result);
                        signatureSchemeApkContentDigests.Add(
                            ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2,
                            getApkContentDigestsFromSigningSchemeResult(v2Result));
                    }
                    catch (ApkSigningBlockUtils.SignatureNotFoundException ignored)
                    {
                        // v2 signature not required
                    }

                    if (result.containsErrors())
                    {
                        return result;
                    }
                }

                // If v4 file is specified, use additional verification on it
                if (mV4SignatureFile != null)
                {
                    ApkSigningBlockUtils.Result v4Result =
                        V4SchemeVerifier.verify(apk, mV4SignatureFile);
                    foundApkSigSchemeIds.Add(
                        ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V4);
                    result.mergeFrom(v4Result);
                    if (result.containsErrors())
                    {
                        return result;
                    }
                }
            }

            // Android O and newer requires that APKs targeting security sandbox version 2 and higher
            // are signed using APK Signature Scheme v2 or newer.
            if (maxSdkVersion >= AndroidSdkVersion.O)
            {
                if (androidManifest == null)
                {
                    androidManifest = getAndroidManifestFromApk(apk, zipSections);
                }

                int targetSandboxVersion =
                    ApkUtils.getTargetSandboxVersionFromBinaryAndroidManifest(androidManifest.slice());
                if (targetSandboxVersion > 1)
                {
                    if (foundApkSigSchemeIds.Count == 0)
                    {
                        result.addError(
                            Issue.NO_SIG_FOR_TARGET_SANDBOX_VERSION,
                            targetSandboxVersion);
                    }
                }
            }

            List<CentralDirectoryRecord> cdRecords =
                V1SchemeVerifier.parseZipCentralDirectory(apk, zipSections);

            // Attempt to verify the APK using JAR signing if necessary. Platforms prior to Android N
            // ignore APK Signature Scheme v2 signatures and always attempt to verify JAR signatures.
            // Android N onwards verifies JAR signatures only if no APK Signature Scheme v2 (or newer
            // scheme) signatures were found.
            if ((minSdkVersion < AndroidSdkVersion.N) || (foundApkSigSchemeIds.Count == 0))
            {
                V1SchemeVerifier.Result v1Result =
                    V1SchemeVerifier.verify(
                        apk,
                        zipSections,
                        supportedSchemeNames,
                        foundApkSigSchemeIds,
                        minSdkVersion.GetValueOrDefault(),
                        maxSdkVersion);
                result.mergeFrom(v1Result);
                signatureSchemeApkContentDigests.Add(
                    ApkSigningBlockUtils.VERSION_JAR_SIGNATURE_SCHEME,
                    getApkContentDigestFromV1SigningScheme(cdRecords, apk, zipSections));
            }

            if (result.containsErrors())
            {
                return result;
            }

            // Verify the SourceStamp, if found in the APK.
            try
            {
                CentralDirectoryRecord sourceStampCdRecord = null;
                foreach (CentralDirectoryRecord cdRecord in cdRecords)
                {
                    if (ApkUtils.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME.Equals(
                            cdRecord.getName()))
                    {
                        sourceStampCdRecord = cdRecord;
                        break;
                    }
                }

                // If SourceStamp file is found inside the APK, there must be a SourceStamp
                // block in the APK signing block as well.
                if (sourceStampCdRecord != null)
                {
                    byte[] sourceStampCertificateDigest =
                        LocalFileRecord.getUncompressedData(
                            apk,
                            sourceStampCdRecord,
                            zipSections.getZipCentralDirectoryOffset());
                    ApkSigResult sourceStampResult =
                        V2SourceStampVerifier.verify(
                            apk,
                            zipSections,
                            sourceStampCertificateDigest,
                            signatureSchemeApkContentDigests,
                            Math.Max(minSdkVersion.GetValueOrDefault(), AndroidSdkVersion.R),
                            maxSdkVersion);
                    result.mergeFrom(sourceStampResult);
                }
            }
            catch (SignatureNotFoundException ignored)
            {
                result.addWarning(Issue.SOURCE_STAMP_SIG_MISSING);
            }
            catch (ZipFormatException e)
            {
                throw new ApkFormatException("Failed to read APK", e);
            }

            if (result.containsErrors())
            {
                return result;
            }

            // Check whether v1 and v2 scheme signer identifies match, provided both v1 and v2
            // signatures verified.
            if ((result.isVerifiedUsingV1Scheme()) && (result.isVerifiedUsingV2Scheme()))
            {
                List<Result.V1SchemeSignerInfo> v1Signers =
                    new List<Result.V1SchemeSignerInfo>(result.getV1SchemeSigners());
                List<Result.V2SchemeSignerInfo> v2Signers =
                    new List<Result.V2SchemeSignerInfo>(result.getV2SchemeSigners());
                List<ByteArray> v1SignerCerts = new List<ByteArray>();
                List<ByteArray> v2SignerCerts = new List<ByteArray>();
                foreach (Result.V1SchemeSignerInfo signer in v1Signers)
                {
                    try
                    {
                        v1SignerCerts.Add(new ByteArray(signer.getCertificate().getEncoded()));
                    }
                    catch (CryptographicException e)
                    {
                        throw new InvalidOperationException(
                            "Failed to encode JAR signer " + signer.getName() + " certs", e);
                    }
                }

                foreach (Result.V2SchemeSignerInfo signer in v2Signers)
                {
                    try
                    {
                        v2SignerCerts.Add(new ByteArray(signer.getCertificate().getEncoded()));
                    }
                    catch (CryptographicException e)
                    {
                        throw new InvalidOperationException(
                            "Failed to encode APK Signature Scheme v2 signer (index: "
                            + signer.getIndex() + ") certs",
                            e);
                    }
                }

                for (int i = 0; i < v1SignerCerts.Count; i++)
                {
                    ByteArray v1Cert = v1SignerCerts[i];
                    if (!v2SignerCerts.Contains(v1Cert))
                    {
                        Result.V1SchemeSignerInfo v1Signer = v1Signers[i];
                        v1Signer.addError(Issue.V2_SIG_MISSING);
                        break;
                    }
                }

                for (int i = 0; i < v2SignerCerts.Count; i++)
                {
                    ByteArray v2Cert = v2SignerCerts[i];
                    if (!v1SignerCerts.Contains(v2Cert))
                    {
                        Result.V2SchemeSignerInfo v2Signer = v2Signers[i];
                        v2Signer.addError(Issue.JAR_SIG_MISSING);
                        break;
                    }
                }
            }

            // If there is a v3 scheme signer and an earlier scheme signer, make sure that there is a
            // match, or in the event of signing certificate rotation, that the v1/v2 scheme signer
            // matches the oldest signing certificate in the provided SigningCertificateLineage
            if (result.isVerifiedUsingV3Scheme()
                && (result.isVerifiedUsingV1Scheme() || result.isVerifiedUsingV2Scheme()))
            {
                SigningCertificateLineage lineage = result.getSigningCertificateLineage();
                X509Certificate oldSignerCert;
                if (result.isVerifiedUsingV1Scheme())
                {
                    List<Result.V1SchemeSignerInfo> v1Signers = result.getV1SchemeSigners();
                    if (v1Signers.Count != 1)
                    {
                        // APK Signature Scheme v3 only supports single-signers, error to sign with
                        // multiple and then only one
                        result.addError(Issue.V3_SIG_MULTIPLE_PAST_SIGNERS);
                    }

                    oldSignerCert = v1Signers[0].mCertChain[0];
                }
                else
                {
                    List<Result.V2SchemeSignerInfo> v2Signers = result.getV2SchemeSigners();
                    if (v2Signers.Count != 1)
                    {
                        // APK Signature Scheme v3 only supports single-signers, error to sign with
                        // multiple and then only one
                        result.addError(Issue.V3_SIG_MULTIPLE_PAST_SIGNERS);
                    }

                    oldSignerCert = v2Signers[0].mCerts[0];
                }

                if (lineage == null)
                {
                    // no signing certificate history with which to contend, just make sure that v3
                    // matches previous versions
                    List<Result.V3SchemeSignerInfo> v3Signers = result.getV3SchemeSigners();
                    if (v3Signers.Count != 1)
                    {
                        // multiple v3 signers should never exist without rotation history, since
                        // multiple signers implies a different signer for different platform versions
                        result.addError(Issue.V3_SIG_MULTIPLE_SIGNERS);
                    }

                    try
                    {
                        if (!oldSignerCert.getEncoded().SequenceEqual(v3Signers[0].mCerts[0].getEncoded()))
                        {
                            result.addError(Issue.V3_SIG_PAST_SIGNERS_MISMATCH);
                        }
                    }
                    catch (CryptographicException e)
                    {
                        // we just go the encoding for the v1/v2 certs above, so must be v3
                        throw new ApplicationException(
                            "Failed to encode APK Signature Scheme v3 signer cert", e);
                    }
                }
                else
                {
                    // we have some signing history, make sure that the root of the history is the same
                    // as our v1/v2 signer
                    try
                    {
                        lineage = lineage.getSubLineage(oldSignerCert);
                        if (lineage.size() != 1)
                        {
                            // the v1/v2 signer was found, but not at the root of the lineage
                            result.addError(Issue.V3_SIG_PAST_SIGNERS_MISMATCH);
                        }
                    }
                    catch (ArgumentException e)
                    {
                        // the v1/v2 signer was not found in the lineage
                        result.addError(Issue.V3_SIG_PAST_SIGNERS_MISMATCH);
                    }
                }
            }


            // If there is a v4 scheme signer, make sure that their certificates match.
            // The apkDigest field in the v4 signature should match the selected v2/v3.
            if (result.isVerifiedUsingV4Scheme())
            {
                List<Result.V4SchemeSignerInfo> v4Signers = result.getV4SchemeSigners();
                if (v4Signers.Count != 1)
                {
                    result.addError(Issue.V4_SIG_MULTIPLE_SIGNERS);
                }

                List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> digestsFromV4 =
                    v4Signers[0].getContentDigests();
                if (digestsFromV4.Count != 1)
                {
                    result.addError(Issue.V4_SIG_V2_V3_DIGESTS_MISMATCH);
                }

                byte[] digestFromV4 = digestsFromV4[0].getValue();

                if (result.isVerifiedUsingV3Scheme())
                {
                    List<Result.V3SchemeSignerInfo> v3Signers = result.getV3SchemeSigners();
                    if (v3Signers.Count != 1)
                    {
                        result.addError(Issue.V4_SIG_MULTIPLE_SIGNERS);
                    }

                    // Compare certificates.
                    checkV4Certificate(v4Signers[0].mCerts, v3Signers[0].mCerts, result);

                    // Compare digests.
                    byte[] digestFromV3 =
                        pickBestDigestForV4(
                            v3Signers[0].getContentDigests());
                    if (!digestFromV4.SequenceEqual(digestFromV3))
                    {
                        result.addError(Issue.V4_SIG_V2_V3_DIGESTS_MISMATCH);
                    }
                }
                else if (result.isVerifiedUsingV2Scheme())
                {
                    List<Result.V2SchemeSignerInfo> v2Signers = result.getV2SchemeSigners();
                    if (v2Signers.Count != 1)
                    {
                        result.addError(Issue.V4_SIG_MULTIPLE_SIGNERS);
                    }

                    // Compare certificates.
                    checkV4Certificate(v4Signers[0].mCerts, v2Signers[0].mCerts, result);

                    // Compare digests.
                    byte[] digestFromV2 =
                        pickBestDigestForV4(
                            v2Signers[0].getContentDigests());
                    if (!digestFromV4.SequenceEqual(digestFromV2))
                    {
                        result.addError(Issue.V4_SIG_V2_V3_DIGESTS_MISMATCH);
                    }
                }
                else
                {
                    throw new ApplicationException("V4 signature must be also verified with V2/V3");
                }
            }

            // If the targetSdkVersion has a minimum required signature scheme version then verify
            // that the APK was signed with at least that version.
            try
            {
                if (androidManifest == null)
                {
                    androidManifest = getAndroidManifestFromApk(apk, zipSections);
                }
            }
            catch (ApkFormatException e)
            {
                // If the manifest is not available then skip the minimum signature scheme requirement
                // to support bundle verification.
            }

            if (androidManifest != null)
            {
                int targetSdkVersion = ApkUtils.getTargetSdkVersionFromBinaryAndroidManifest(
                    androidManifest.slice());
                int minSchemeVersion = getMinimumSignatureSchemeVersionForTargetSdk(targetSdkVersion);
                // The platform currently only enforces a single minimum signature scheme version, but
                // when later platform versions support another minimum version this will need to be
                // expanded to verify the minimum based on the target and maximum SDK version.
                if (minSchemeVersion > ApkSigningBlockUtils.VERSION_JAR_SIGNATURE_SCHEME
                    && maxSdkVersion >= targetSdkVersion)
                {
                    switch (minSchemeVersion)
                    {
                        case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2:
                            if (result.isVerifiedUsingV2Scheme())
                            {
                                break;
                            }

                            goto case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3;

                        // Allow this case to fall through to the next as a signature satisfying a
                        // later scheme version will also satisfy this requirement.
                        case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3:
                            if (result.isVerifiedUsingV3Scheme())
                            {
                                break;
                            }

                            result.addError(Issue.MIN_SIG_SCHEME_FOR_TARGET_SDK_NOT_MET,
                                targetSdkVersion,
                                minSchemeVersion);
                            break;
                    }
                }
            }

            if (result.containsErrors())
            {
                return result;
            }

            // Verified
            result.setVerified();
            if (result.isVerifiedUsingV3Scheme())
            {
                List<Result.V3SchemeSignerInfo> v3Signers = result.getV3SchemeSigners();
                result.addSignerCertificate(v3Signers.Last().getCertificate());
            }
            else if (result.isVerifiedUsingV2Scheme())
            {
                foreach (Result.V2SchemeSignerInfo signerInfo in result.getV2SchemeSigners())
                {
                    result.addSignerCertificate(signerInfo.getCertificate());
                }
            }
            else if (result.isVerifiedUsingV1Scheme())
            {
                foreach (Result.V1SchemeSignerInfo signerInfo in result.getV1SchemeSigners())
                {
                    result.addSignerCertificate(signerInfo.getCertificate());
                }
            }
            else
            {
                throw new ApplicationException(
                    "APK verified, but has not verified using any of v1, v2 or v3 schemes");
            }

            return result;
        }

        /**
     * Verifies and returns the minimum SDK version, either as provided to the builder or as read
     * from the {@code apk}'s AndroidManifest.xml.
     */
        private int? verifyAndGetMinSdkVersion(DataSource apk, ZipSections zipSections)
        {
            if (mMinSdkVersion != null)
            {
                if (mMinSdkVersion < 0)
                {
                    throw new ArgumentException(
                        "minSdkVersion must not be negative: " + mMinSdkVersion);
                }

                if ((mMinSdkVersion != null) && (mMinSdkVersion > mMaxSdkVersion))
                {
                    throw new ArgumentException(
                        "minSdkVersion (" + mMinSdkVersion + ") > maxSdkVersion (" + mMaxSdkVersion
                        + ")");
                }

                return mMinSdkVersion;
            }

            ByteBuffer androidManifest = null;
            // Need to obtain minSdkVersion from the APK's AndroidManifest.xml
            if (androidManifest == null)
            {
                androidManifest = getAndroidManifestFromApk(apk, zipSections);
            }

            int minSdkVersion =
                ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(androidManifest.slice());
            if (minSdkVersion > mMaxSdkVersion)
            {
                throw new ArgumentException(
                    "minSdkVersion from APK (" + minSdkVersion + ") > maxSdkVersion ("
                    + mMaxSdkVersion + ")");
            }

            return minSdkVersion;
        }

        /**
     * Returns the mapping of signature scheme version to signature scheme name for all signature
     * schemes starting from V2 supported by the {@code maxSdkVersion}.
     */
        private static Dictionary<int, String> getSupportedSchemeNames(int maxSdkVersion)
        {
            Dictionary<int, String> supportedSchemeNames;
            if (maxSdkVersion >= AndroidSdkVersion.P)
            {
                supportedSchemeNames = SUPPORTED_APK_SIG_SCHEME_NAMES;
            }
            else if (maxSdkVersion >= AndroidSdkVersion.N)
            {
                supportedSchemeNames = new Dictionary<int, string>(1);
                supportedSchemeNames.Add(ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2,
                    SUPPORTED_APK_SIG_SCHEME_NAMES[ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2]);
            }
            else
            {
                supportedSchemeNames = new Dictionary<int, string>();
            }

            return supportedSchemeNames;
        }

        /**
     * Verifies the APK's source stamp signature and returns the result of the verification.
     *
     * <p>The APK's source stamp can be considered verified if the result's {@link
     * Result#isVerified} returns {@code true}. The details of the source stamp verification can
     * be obtained from the result's {@link Result#getSourceStampInfo()}} including the success or
     * failure cause from {@link Result.SourceStampInfo#getSourceStampVerificationStatus()}. If the
     * verification fails additional details regarding the failure can be obtained from {@link
     * Result#getAllErrors()}}.
     */
        public Result verifySourceStamp()
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
        public Result verifySourceStamp(String expectedCertDigest)
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
                return createSourceStampResultWithError(
                    Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR,
                    Issue.UNEXPECTED_EXCEPTION, e);
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
        private Result verifySourceStamp(DataSource apk, String expectedCertDigest)
        {
            try
            {
                ZipSections zipSections = ApkUtils.findZipSections(apk);
                int? minSdkVersion = verifyAndGetMinSdkVersion(apk, zipSections);

                // Attempt to obtain the source stamp's certificate digest from the APK.
                List<CentralDirectoryRecord> cdRecords =
                    V1SchemeVerifier.parseZipCentralDirectory(apk, zipSections);
                CentralDirectoryRecord sourceStampCdRecord = null;
                foreach (CentralDirectoryRecord cdRecord in cdRecords)
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
                        ApkSigningBlockUtils.Result stampResult = new ApkSigningBlockUtils.Result(
                            ApkSigningBlockUtils.VERSION_SOURCE_STAMP);
                        ApkSigningBlockUtils.findSignature(apk, zipSections,
                            SourceStampConstants.V2_SOURCE_STAMP_BLOCK_ID, stampResult);
                        stampSigningBlockFound = true;
                    }
                    catch (ApkSigningBlockUtils.SignatureNotFoundException e)
                    {
                        stampSigningBlockFound = false;
                    }

                    if (stampSigningBlockFound)
                    {
                        return createSourceStampResultWithError(
                            Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_NOT_VERIFIED,
                            Issue.SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST);
                    }
                    else
                    {
                        return createSourceStampResultWithError(
                            Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_MISSING,
                            Issue.SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING);
                    }
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
                    String actualCertDigest = ApkSigningBlockUtils.toHex(sourceStampCertificateDigest);
                    if (!expectedCertDigest.Equals(actualCertDigest, StringComparison.OrdinalIgnoreCase))
                    {
                        return createSourceStampResultWithError(
                            Result.SourceStampInfo.SourceStampVerificationStatus
                                .CERT_DIGEST_MISMATCH,
                            Issue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH, actualCertDigest,
                            expectedCertDigest);
                    }
                }

                Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests =
                    new Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>>();
                Dictionary<int, String> supportedSchemeNames = getSupportedSchemeNames(mMaxSdkVersion);
                ISet<int> foundApkSigSchemeIds = new HashSet<int>(2);

                Result result = new Result();
                ApkSigningBlockUtils.Result v3Result = null;
                if (mMaxSdkVersion >= AndroidSdkVersion.P)
                {
                    v3Result = getApkContentDigests(apk, zipSections, foundApkSigSchemeIds,
                        supportedSchemeNames, signatureSchemeApkContentDigests,
                        ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3,
                        Math.Max(minSdkVersion.GetValueOrDefault(), AndroidSdkVersion.P));
                    if (v3Result != null && v3Result.containsErrors())
                    {
                        result.mergeFrom(v3Result);
                        return mergeSourceStampResult(
                            Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR,
                            result);
                    }
                }

                ApkSigningBlockUtils.Result v2Result = null;
                if (mMaxSdkVersion >= AndroidSdkVersion.N && (minSdkVersion < AndroidSdkVersion.P
                                                              || foundApkSigSchemeIds.Count == 0))
                {
                    v2Result = getApkContentDigests(apk, zipSections, foundApkSigSchemeIds,
                        supportedSchemeNames, signatureSchemeApkContentDigests,
                        ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2,
                        Math.Max(minSdkVersion.GetValueOrDefault(), AndroidSdkVersion.N));
                    if (v2Result != null && v2Result.containsErrors())
                    {
                        result.mergeFrom(v2Result);
                        return mergeSourceStampResult(
                            Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR,
                            result);
                    }
                }

                if (minSdkVersion < AndroidSdkVersion.N || foundApkSigSchemeIds.Count == 0)
                {
                    signatureSchemeApkContentDigests.Add(ApkSigningBlockUtils.VERSION_JAR_SIGNATURE_SCHEME,
                        getApkContentDigestFromV1SigningScheme(cdRecords, apk, zipSections));
                }

                ApkSigResult sourceStampResult =
                    V2SourceStampVerifier.verify(
                        apk,
                        zipSections,
                        sourceStampCertificateDigest,
                        signatureSchemeApkContentDigests,
                        minSdkVersion,
                        mMaxSdkVersion);
                result.mergeFrom(sourceStampResult);
                // Since the caller is only seeking to verify the source stamp the Result can be marked
                // as verified if the source stamp verification was successful.
                if (sourceStampResult.verified)
                {
                    result.setVerified();
                }
                else
                {
                    // To prevent APK signature verification with a failed / missing source stamp the
                    // source stamp verification will only log warnings; to allow the caller to capture
                    // the failure reason treat all warnings as errors.
                    result.setWarningsAsErrors(true);
                }

                return result;
            }
            catch (Exception e) when (e is ApkFormatException || e is IOException | e is ZipFormatException)
            {
                return createSourceStampResultWithError(
                    Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR,
                    Issue.MALFORMED_APK, e);
            }
            catch (CryptographicException e)
            {
                return createSourceStampResultWithError(
                    Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR,
                    Issue.UNEXPECTED_EXCEPTION, e);
            }
            catch (SignatureNotFoundException e)
            {
                return createSourceStampResultWithError(
                    Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_NOT_VERIFIED,
                    Issue.SOURCE_STAMP_SIG_MISSING);
            }
        }

        /**
     * Creates and returns a {@code Result} that can be returned for source stamp verification
     * with the provided source stamp {@code verificationStatus}, and logs an error for the
     * specified {@code issue} and {@code params}.
     */
        private static Result createSourceStampResultWithError(
            Result.SourceStampInfo.SourceStampVerificationStatus verificationStatus, Issue issue,
            params Object[] parameters)
        {
            Result result = new Result();
            result.addError(issue, parameters);
            return mergeSourceStampResult(verificationStatus, result);
        }

        /**
     * Creates a new {@link Result.SourceStampInfo} under the provided {@code result} and sets the
     * source stamp status to the provided {@code verificationStatus}.
     */
        private static Result mergeSourceStampResult(
            Result.SourceStampInfo.SourceStampVerificationStatus verificationStatus,
            Result result)
        {
            result.mSourceStampInfo = new Result.SourceStampInfo(verificationStatus);
            return result;
        }

        /**
     * Obtains the APK content digest(s) and adds them to the provided {@code
     * sigSchemeApkContentDigests}, returning an {@code ApkSigningBlockUtils.Result} that can be
     * merged with a {@code Result} to notify the client of any errors.
     *
     * <p>Note, this method currently only supports signature scheme V2 and V3; to obtain the
     * content digests for V1 signatures use {@link
     * #getApkContentDigestFromV1SigningScheme(List, DataSource, ZipSections)}. If a
     * signature scheme version other than V2 or V3 is provided a {@code null} value will be
     * returned.
     */
        private ApkSigningBlockUtils.Result getApkContentDigests(DataSource apk,
            ZipSections zipSections, ISet<int> foundApkSigSchemeIds,
            Dictionary<int, String> supportedSchemeNames,
            Dictionary<int, Dictionary<ContentDigestAlgorithm, byte[]>> sigSchemeApkContentDigests,
            int apkSigSchemeVersion, int minSdkVersion)
        {
            if (!(apkSigSchemeVersion == ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2
                  || apkSigSchemeVersion == ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3))
            {
                return null;
            }

            ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(apkSigSchemeVersion);
            SignatureInfo signatureInfo;
            try
            {
                int sigSchemeBlockId = apkSigSchemeVersion == ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3
                    ? V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID
                    : V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID;
                signatureInfo = ApkSigningBlockUtils.findSignature(apk, zipSections,
                    sigSchemeBlockId, result);
            }
            catch (ApkSigningBlockUtils.SignatureNotFoundException e)
            {
                return null;
            }

            foundApkSigSchemeIds.Add(apkSigSchemeVersion);

            ISet<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<ContentDigestAlgorithm>(1);
            if (apkSigSchemeVersion == ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2)
            {
                V2SchemeVerifier.parseSigners(signatureInfo.signatureBlock,
                    contentDigestsToVerify, supportedSchemeNames,
                    foundApkSigSchemeIds, minSdkVersion, mMaxSdkVersion, result);
            }
            else
            {
                V3SchemeVerifier.parseSigners(signatureInfo.signatureBlock,
                    contentDigestsToVerify, result);
            }

            Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests =
                new Dictionary<ContentDigestAlgorithm, byte[]>();
            foreach (ApkSigningBlockUtils.Result.SignerInfo signerInfo in result.signers)
            {
                foreach (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest contentDigest in
                         signerInfo.contentDigests)
                {
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(
                        contentDigest.getSignatureAlgorithmId());
                    if (signatureAlgorithm == null)
                    {
                        continue;
                    }

                    apkContentDigests.Add(signatureAlgorithm.getContentDigestAlgorithm(),
                        contentDigest.getValue());
                }
            }

            sigSchemeApkContentDigests.Add(apkSigSchemeVersion, apkContentDigests);
            return result;
        }

        private static void checkV4Certificate(List<X509Certificate> v4Certs,
            List<X509Certificate> v2v3Certs, Result result)
        {
            try
            {
                byte[] v4Cert = v4Certs[0].getEncoded();
                byte[] cert = v2v3Certs[0].getEncoded();
                if (!cert.SequenceEqual(v4Cert))
                {
                    result.addError(Issue.V4_SIG_V2_V3_SIGNERS_MISMATCH);
                }
            }
            catch (CryptographicException e)
            {
                throw new ApplicationException("Failed to encode APK signer cert", e);
            }
        }

        private static byte[] pickBestDigestForV4(
            List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> contentDigests)
        {
            Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests =
                new Dictionary<ContentDigestAlgorithm, byte[]>();
            collectApkContentDigests(contentDigests, apkContentDigests);
            return ApkSigningBlockUtils.pickBestDigestForV4(apkContentDigests);
        }

        private static Dictionary<ContentDigestAlgorithm, byte[]> getApkContentDigestsFromSigningSchemeResult(
            ApkSigningBlockUtils.Result apkSigningSchemeResult)
        {
            Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests =
                new Dictionary<ContentDigestAlgorithm, byte[]>();
            foreach (ApkSigningBlockUtils.Result.SignerInfo signerInfo in apkSigningSchemeResult.signers)
            {
                collectApkContentDigests(signerInfo.contentDigests, apkContentDigests);
            }

            return apkContentDigests;
        }

        private static Dictionary<ContentDigestAlgorithm, byte[]> getApkContentDigestFromV1SigningScheme(
            List<CentralDirectoryRecord> cdRecords,
            DataSource apk,
            ZipSections zipSections)
        {
            CentralDirectoryRecord manifestCdRecord = null;
            Dictionary<ContentDigestAlgorithm, byte[]> v1ContentDigest =
                new Dictionary<ContentDigestAlgorithm, byte[]>();
            foreach (CentralDirectoryRecord cdRecord in cdRecords)
            {
                if (V1SchemeConstants.MANIFEST_ENTRY_NAME.Equals(cdRecord.getName()))
                {
                    manifestCdRecord = cdRecord;
                    break;
                }
            }

            if (manifestCdRecord == null)
            {
                // No JAR signing manifest file found. For SourceStamp verification, returning an empty
                // digest is enough since this would affect the readonly digest signed by the stamp, and
                // thus an empty digest will invalidate that signature.
                return v1ContentDigest;
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

        private static void collectApkContentDigests(
            List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> contentDigests,
            Dictionary<ContentDigestAlgorithm, byte[]> apkContentDigests)
        {
            foreach (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest contentDigest in contentDigests)
            {
                SignatureAlgorithm signatureAlgorithm =
                    SignatureAlgorithm.findById(contentDigest.getSignatureAlgorithmId());
                if (signatureAlgorithm == null)
                {
                    continue;
                }

                ContentDigestAlgorithm contentDigestAlgorithm =
                    signatureAlgorithm.getContentDigestAlgorithm();
                apkContentDigests.Add(contentDigestAlgorithm, contentDigest.getValue());
            }
        }

        private static ByteBuffer getAndroidManifestFromApk(
            DataSource apk, ZipSections zipSections)
        {
            List<CentralDirectoryRecord> cdRecords =
                V1SchemeVerifier.parseZipCentralDirectory(apk, zipSections);
            try
            {
                return ApkSigner.getAndroidManifestFromApk(
                    cdRecords,
                    apk.slice(0, zipSections.getZipCentralDirectoryOffset()));
            }
            catch (ZipFormatException e)
            {
                throw new ApkFormatException("Failed to read AndroidManifest.xml", e);
            }
        }

        private static int getMinimumSignatureSchemeVersionForTargetSdk(int targetSdkVersion)
        {
            if (targetSdkVersion >= AndroidSdkVersion.R)
            {
                return ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2;
            }

            return ApkSigningBlockUtils.VERSION_JAR_SIGNATURE_SCHEME;
        }

        /**
     * Result of verifying an APKs signatures. The APK can be considered verified iff
     * {@link #isVerified()} returns {@code true}.
     */
        public class Result
        {
            private readonly List<IssueWithParams> mErrors = new List<IssueWithParams>();
            private readonly List<IssueWithParams> mWarnings = new List<IssueWithParams>();
            private readonly List<X509Certificate> mSignerCerts = new List<X509Certificate>();
            private readonly List<V1SchemeSignerInfo> mV1SchemeSigners = new List<V1SchemeSignerInfo>();
            private readonly List<V1SchemeSignerInfo> mV1SchemeIgnoredSigners = new List<V1SchemeSignerInfo>();
            private readonly List<V2SchemeSignerInfo> mV2SchemeSigners = new List<V2SchemeSignerInfo>();
            private readonly List<V3SchemeSignerInfo> mV3SchemeSigners = new List<V3SchemeSignerInfo>();
            private readonly List<V4SchemeSignerInfo> mV4SchemeSigners = new List<V4SchemeSignerInfo>();
            public SourceStampInfo mSourceStampInfo;

            private bool mVerified;
            private bool mVerifiedUsingV1Scheme;
            private bool mVerifiedUsingV2Scheme;
            private bool mVerifiedUsingV3Scheme;
            private bool mVerifiedUsingV4Scheme;
            private bool mSourceStampVerified;
            private bool mWarningsAsErrors;
            private SigningCertificateLineage mSigningCertificateLineage;

            /**
         * Returns {@code true} if the APK's signatures verified.
         */
            public bool isVerified()
            {
                return mVerified;
            }

            public void setVerified()
            {
                mVerified = true;
            }

            /**
         * Returns {@code true} if the APK's JAR signatures verified.
         */
            public bool isVerifiedUsingV1Scheme()
            {
                return mVerifiedUsingV1Scheme;
            }

            /**
         * Returns {@code true} if the APK's APK Signature Scheme v2 signatures verified.
         */
            public bool isVerifiedUsingV2Scheme()
            {
                return mVerifiedUsingV2Scheme;
            }

            /**
         * Returns {@code true} if the APK's APK Signature Scheme v3 signature verified.
         */
            public bool isVerifiedUsingV3Scheme()
            {
                return mVerifiedUsingV3Scheme;
            }

            /**
         * Returns {@code true} if the APK's APK Signature Scheme v4 signature verified.
         */
            public bool isVerifiedUsingV4Scheme()
            {
                return mVerifiedUsingV4Scheme;
            }

            /**
         * Returns {@code true} if the APK's SourceStamp signature verified.
         */
            public bool isSourceStampVerified()
            {
                return mSourceStampVerified;
            }

            /**
         * Returns the verified signers' certificates, one per signer.
         */
            public List<X509Certificate> getSignerCertificates()
            {
                return mSignerCerts;
            }

            public void addSignerCertificate(X509Certificate cert)
            {
                mSignerCerts.Add(cert);
            }

            /**
         * Returns information about JAR signers associated with the APK's signature. These are the
         * signers used by Android.
         *
         * @see #getV1SchemeIgnoredSigners()
         */
            public List<V1SchemeSignerInfo> getV1SchemeSigners()
            {
                return mV1SchemeSigners;
            }

            /**
         * Returns information about JAR signers ignored by the APK's signature verification
         * process. These signers are ignored by Android. However, each signer's errors or warnings
         * will contain information about why they are ignored.
         *
         * @see #getV1SchemeSigners()
         */
            public List<V1SchemeSignerInfo> getV1SchemeIgnoredSigners()
            {
                return mV1SchemeIgnoredSigners;
            }

            /**
         * Returns information about APK Signature Scheme v2 signers associated with the APK's
         * signature.
         */
            public List<V2SchemeSignerInfo> getV2SchemeSigners()
            {
                return mV2SchemeSigners;
            }

            /**
         * Returns information about APK Signature Scheme v3 signers associated with the APK's
         * signature.
         *
         * <note> Multiple signers represent different targeted platform versions, not
         * a signing identity of multiple signers.  APK Signature Scheme v3 only supports single
         * signer identities.</note>
         */
            public List<V3SchemeSignerInfo> getV3SchemeSigners()
            {
                return mV3SchemeSigners;
            }

            public List<V4SchemeSignerInfo> getV4SchemeSigners()
            {
                return mV4SchemeSigners;
            }

            /**
         * Returns information about SourceStamp associated with the APK's signature.
         */
            public SourceStampInfo getSourceStampInfo()
            {
                return mSourceStampInfo;
            }

            /**
         * Returns the combined SigningCertificateLineage associated with this APK's APK Signature
         * Scheme v3 signing block.
         */
            public SigningCertificateLineage getSigningCertificateLineage()
            {
                return mSigningCertificateLineage;
            }

            public void addError(Issue msg, params Object[] parameters)
            {
                mErrors.Add(new IssueWithParams(msg, parameters));
            }

            public void addWarning(Issue msg, params Object[] parameters)
            {
                mWarnings.Add(new IssueWithParams(msg, parameters));
            }

            /**
         * Sets whether warnings should be treated as errors.
         */
            public void setWarningsAsErrors(bool value)
            {
                mWarningsAsErrors = value;
            }

            /**
         * Returns errors encountered while verifying the APK's signatures.
         */
            public List<IssueWithParams> getErrors()
            {
                if (!mWarningsAsErrors)
                {
                    return mErrors;
                }
                else
                {
                    List<IssueWithParams> allErrors = new List<IssueWithParams>();
                    allErrors.AddRange(mErrors);
                    allErrors.AddRange(mWarnings);
                    return allErrors;
                }
            }

            /**
         * Returns warnings encountered while verifying the APK's signatures.
         */
            public List<IssueWithParams> getWarnings()
            {
                return mWarnings;
            }

            public void mergeFrom(V1SchemeVerifier.Result source)
            {
                mVerifiedUsingV1Scheme = source.verified;
                mErrors.AddRange(source.getErrors());
                mWarnings.AddRange(source.getWarnings());
                foreach (V1SchemeVerifier.Result.SignerInfo signer in source.signers)
                {
                    mV1SchemeSigners.Add(new V1SchemeSignerInfo(signer));
                }

                foreach (V1SchemeVerifier.Result.SignerInfo signer in source.ignoredSigners)
                {
                    mV1SchemeIgnoredSigners.Add(new V1SchemeSignerInfo(signer));
                }
            }

            public void mergeFrom(ApkSigResult source)
            {
                switch (source.signatureSchemeVersion)
                {
                    case ApkSigningBlockUtils.VERSION_SOURCE_STAMP:
                        mSourceStampVerified = source.verified;
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

            public void mergeFrom(ApkSigningBlockUtils.Result source)
            {
                switch (source.signatureSchemeVersion)
                {
                    case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2:
                        mVerifiedUsingV2Scheme = source.verified;
                        foreach (ApkSigningBlockUtils.Result.SignerInfo signer in source.signers)
                        {
                            mV2SchemeSigners.Add(new V2SchemeSignerInfo(signer));
                        }

                        break;
                    case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3:
                        mVerifiedUsingV3Scheme = source.verified;
                        foreach (ApkSigningBlockUtils.Result.SignerInfo signer in source.signers)
                        {
                            mV3SchemeSigners.Add(new V3SchemeSignerInfo(signer));
                        }

                        mSigningCertificateLineage = source.signingCertificateLineage;
                        break;
                    case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V4:
                        mVerifiedUsingV4Scheme = source.verified;
                        foreach (ApkSigningBlockUtils.Result.SignerInfo signer in source.signers)
                        {
                            mV4SchemeSigners.Add(new V4SchemeSignerInfo(signer));
                        }

                        break;
                    case ApkSigningBlockUtils.VERSION_SOURCE_STAMP:
                        mSourceStampVerified = source.verified;
                        if (source.signers.Count == 0)
                        {
                            mSourceStampInfo = new SourceStampInfo(source.signers[0]);
                        }

                        break;
                    default:
                        throw new ArgumentException("Unknown Signing Block Scheme Id");
                }
            }

            /**
         * Returns {@code true} if an error was encountered while verifying the APK. Any error
         * prevents the APK from being considered verified.
         */
            public bool containsErrors()
            {
                if (mErrors.Count != 0)
                {
                    return true;
                }

                if (mWarningsAsErrors && mWarnings.Count != 0)
                {
                    return true;
                }

                if (mV1SchemeSigners.Count != 0)
                {
                    foreach (V1SchemeSignerInfo signer in mV1SchemeSigners)
                    {
                        if (signer.containsErrors())
                        {
                            return true;
                        }

                        if (mWarningsAsErrors && signer.getWarnings().Count != 0)
                        {
                            return true;
                        }
                    }
                }

                if (mV2SchemeSigners.Count != 0)
                {
                    foreach (V2SchemeSignerInfo signer in mV2SchemeSigners)
                    {
                        if (signer.containsErrors())
                        {
                            return true;
                        }

                        if (mWarningsAsErrors && signer.getWarnings().Count != 0)
                        {
                            return true;
                        }
                    }
                }

                if (mV3SchemeSigners.Count != 0)
                {
                    foreach (V3SchemeSignerInfo signer in mV3SchemeSigners)
                    {
                        if (signer.containsErrors())
                        {
                            return true;
                        }

                        if (mWarningsAsErrors && signer.getWarnings().Count != 0)
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

                    if (mWarningsAsErrors && mSourceStampInfo.getWarnings().Count != 0)
                    {
                        return true;
                    }
                }

                return false;
            }

            /**
         * Returns all errors for this result, including any errors from signature scheme signers
         * and the source stamp.
         */
            public List<ApkVerificationIssue> getAllErrors()
            {
                List<ApkVerificationIssue> errors = new List<ApkVerificationIssue>();
                errors.AddRange(mErrors);
                if (mWarningsAsErrors)
                {
                    errors.AddRange(mWarnings);
                }

                if (mV1SchemeSigners.Count != 0)
                {
                    foreach (V1SchemeSignerInfo signer in mV1SchemeSigners)
                    {
                        errors.AddRange(signer.mErrors);
                        if (mWarningsAsErrors)
                        {
                            errors.AddRange(signer.getWarnings());
                        }
                    }
                }

                if (mV2SchemeSigners.Count != 0)
                {
                    foreach (V2SchemeSignerInfo signer in mV2SchemeSigners)
                    {
                        errors.AddRange(signer.mErrors);
                        if (mWarningsAsErrors)
                        {
                            errors.AddRange(signer.getWarnings());
                        }
                    }
                }

                if (mV3SchemeSigners.Count != 0)
                {
                    foreach (V3SchemeSignerInfo signer in mV3SchemeSigners)
                    {
                        errors.AddRange(signer.mErrors);
                        if (mWarningsAsErrors)
                        {
                            errors.AddRange(signer.getWarnings());
                        }
                    }
                }

                if (mSourceStampInfo != null)
                {
                    errors.AddRange(mSourceStampInfo.getErrors());
                    if (mWarningsAsErrors)
                    {
                        errors.AddRange(mSourceStampInfo.getWarnings());
                    }
                }

                return errors;
            }

            /**
         * Information about a JAR signer associated with the APK's signature.
         */
            public class V1SchemeSignerInfo
            {
                private readonly String mName;
                public readonly List<X509Certificate> mCertChain;
                private readonly String mSignatureBlockFileName;
                private readonly String mSignatureFileName;

                public readonly List<IssueWithParams> mErrors;
                private readonly List<IssueWithParams> mWarnings;

                public V1SchemeSignerInfo(V1SchemeVerifier.Result.SignerInfo result)
                {
                    mName = result.name;
                    mCertChain = result.certChain;
                    mSignatureBlockFileName = result.signatureBlockFileName;
                    mSignatureFileName = result.signatureFileName;
                    mErrors = result.getErrors();
                    mWarnings = result.getWarnings();
                }

                /**
             * Returns a user-friendly name of the signer.
             */
                public String getName()
                {
                    return mName;
                }

                /**
             * Returns the name of the JAR entry containing this signer's JAR signature block file.
             */
                public String getSignatureBlockFileName()
                {
                    return mSignatureBlockFileName;
                }

                /**
             * Returns the name of the JAR entry containing this signer's JAR signature file.
             */
                public String getSignatureFileName()
                {
                    return mSignatureFileName;
                }

                /**
             * Returns this signer's signing certificate or {@code null} if not available. The
             * certificate is guaranteed to be available if no errors were encountered during
             * verification (see {@link #containsErrors()}.
             *
             * <p>This certificate contains the signer's public key.
             */
                public X509Certificate getCertificate()
                {
                    return mCertChain.Count == 0 ? null : mCertChain[0];
                }

                /**
             * Returns the certificate chain for the signer's public key. The certificate containing
             * the public key is first, followed by the certificate (if any) which issued the
             * signing certificate, and so forth. An empty list may be returned if an error was
             * encountered during verification (see {@link #containsErrors()}).
             */
                public List<X509Certificate> getCertificateChain()
                {
                    return mCertChain;
                }

                /**
             * Returns {@code true} if an error was encountered while verifying this signer's JAR
             * signature. Any error prevents the signer's signature from being considered verified.
             */
                public bool containsErrors()
                {
                    return mErrors.Count != 0;
                }

                /**
             * Returns errors encountered while verifying this signer's JAR signature. Any error
             * prevents the signer's signature from being considered verified.
             */
                public List<IssueWithParams> getErrors()
                {
                    return mErrors;
                }

                /**
             * Returns warnings encountered while verifying this signer's JAR signature. Warnings
             * do not prevent the signer's signature from being considered verified.
             */
                public List<IssueWithParams> getWarnings()
                {
                    return mWarnings;
                }

                public void addError(Issue msg, params Object[] parameters)
                {
                    mErrors.Add(new IssueWithParams(msg, parameters));
                }
            }

            /**
         * Information about an APK Signature Scheme v2 signer associated with the APK's signature.
         */
            public class V2SchemeSignerInfo
            {
                private readonly int mIndex;
                public readonly List<X509Certificate> mCerts;

                public readonly List<ApkVerificationIssue> mErrors;
                private readonly List<ApkVerificationIssue> mWarnings;

                private readonly List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest>
                    mContentDigests;

                public V2SchemeSignerInfo(ApkSigningBlockUtils.Result.SignerInfo result)
                {
                    mIndex = result.index;
                    mCerts = result.certs;
                    mErrors = result.getErrors();
                    mWarnings = result.getWarnings();
                    mContentDigests = result.contentDigests;
                }

                /**
             * Returns this signer's {@code 0}-based index in the list of signers contained in the
             * APK's APK Signature Scheme v2 signature.
             */
                public int getIndex()
                {
                    return mIndex;
                }

                /**
             * Returns this signer's signing certificate or {@code null} if not available. The
             * certificate is guaranteed to be available if no errors were encountered during
             * verification (see {@link #containsErrors()}.
             *
             * <p>This certificate contains the signer's public key.
             */
                public X509Certificate getCertificate()
                {
                    return mCerts.Count == 0 ? null : mCerts[0];
                }

                /**
             * Returns this signer's certificates. The first certificate is for the signer's public
             * key. An empty list may be returned if an error was encountered during verification
             * (see {@link #containsErrors()}).
             */
                public List<X509Certificate> getCertificates()
                {
                    return mCerts;
                }

                public void addError(Issue msg, params Object[] parameters)
                {
                    mErrors.Add(new IssueWithParams(msg, parameters));
                }

                public bool containsErrors()
                {
                    return mErrors.Count != 0;
                }

                public List<ApkVerificationIssue> getErrors()
                {
                    return mErrors;
                }

                public List<ApkVerificationIssue> getWarnings()
                {
                    return mWarnings;
                }

                public List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> getContentDigests()
                {
                    return mContentDigests;
                }
            }

            /**
         * Information about an APK Signature Scheme v3 signer associated with the APK's signature.
         */
            public class V3SchemeSignerInfo
            {
                private readonly int mIndex;
                public readonly List<X509Certificate> mCerts;

                public readonly List<ApkVerificationIssue> mErrors;
                private readonly List<ApkVerificationIssue> mWarnings;

                private readonly List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest>
                    mContentDigests;

                public V3SchemeSignerInfo(ApkSigningBlockUtils.Result.SignerInfo result)
                {
                    mIndex = result.index;
                    mCerts = result.certs;
                    mErrors = result.getErrors();
                    mWarnings = result.getWarnings();
                    mContentDigests = result.contentDigests;
                }

                /**
             * Returns this signer's {@code 0}-based index in the list of signers contained in the
             * APK's APK Signature Scheme v3 signature.
             */
                public int getIndex()
                {
                    return mIndex;
                }

                /**
             * Returns this signer's signing certificate or {@code null} if not available. The
             * certificate is guaranteed to be available if no errors were encountered during
             * verification (see {@link #containsErrors()}.
             *
             * <p>This certificate contains the signer's public key.
             */
                public X509Certificate getCertificate()
                {
                    return mCerts.Count == 0 ? null : mCerts[0];
                }

                /**
             * Returns this signer's certificates. The first certificate is for the signer's public
             * key. An empty list may be returned if an error was encountered during verification
             * (see {@link #containsErrors()}).
             */
                public List<X509Certificate> getCertificates()
                {
                    return mCerts;
                }

                public bool containsErrors()
                {
                    return mErrors.Count == 0;
                }

                public List<ApkVerificationIssue> getErrors()
                {
                    return mErrors;
                }

                public List<ApkVerificationIssue> getWarnings()
                {
                    return mWarnings;
                }

                public List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> getContentDigests()
                {
                    return mContentDigests;
                }
            }

            /**
         * Information about an APK Signature Scheme V4 signer associated with the APK's
         * signature.
         */
            public class V4SchemeSignerInfo
            {
                private readonly int mIndex;
                public readonly List<X509Certificate> mCerts;

                private readonly List<ApkVerificationIssue> mErrors;
                private readonly List<ApkVerificationIssue> mWarnings;

                private readonly List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest>
                    mContentDigests;

                public V4SchemeSignerInfo(ApkSigningBlockUtils.Result.SignerInfo result)
                {
                    mIndex = result.index;
                    mCerts = result.certs;
                    mErrors = result.getErrors();
                    mWarnings = result.getWarnings();
                    mContentDigests = result.contentDigests;
                }

                /**
             * Returns this signer's {@code 0}-based index in the list of signers contained in the
             * APK's APK Signature Scheme v3 signature.
             */
                public int getIndex()
                {
                    return mIndex;
                }

                /**
             * Returns this signer's signing certificate or {@code null} if not available. The
             * certificate is guaranteed to be available if no errors were encountered during
             * verification (see {@link #containsErrors()}.
             *
             * <p>This certificate contains the signer's public key.
             */
                public X509Certificate getCertificate()
                {
                    return mCerts.Count == 0 ? null : mCerts[0];
                }

                /**
             * Returns this signer's certificates. The first certificate is for the signer's public
             * key. An empty list may be returned if an error was encountered during verification
             * (see {@link #containsErrors()}).
             */
                public List<X509Certificate> getCertificates()
                {
                    return mCerts;
                }

                public bool containsErrors()
                {
                    return mErrors.Count != 0;
                }

                public List<ApkVerificationIssue> getErrors()
                {
                    return mErrors;
                }

                public List<ApkVerificationIssue> getWarnings()
                {
                    return mWarnings;
                }

                public List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> getContentDigests()
                {
                    return mContentDigests;
                }
            }

            /**
         * Information about SourceStamp associated with the APK's signature.
         */
            public class SourceStampInfo
            {
                public enum SourceStampVerificationStatus
                {
                    /** The stamp is present and was successfully verified. */
                    STAMP_VERIFIED,

                    /** The stamp is present but failed verification. */
                    STAMP_VERIFICATION_FAILED,

                    /** The expected cert digest did not match the digest in the APK. */
                    CERT_DIGEST_MISMATCH,

                    /** The stamp is not present at all. */
                    STAMP_MISSING,

                    /** The stamp is at least partially present, but was not able to be verified. */
                    STAMP_NOT_VERIFIED,

                    /** The stamp was not able to be verified due to an unexpected error. */
                    VERIFICATION_ERROR
                }

                private readonly List<X509Certificate> mCertificates;
                private readonly List<X509Certificate> mCertificateLineage;

                private readonly List<IssueWithParams> mErrors;
                private readonly List<IssueWithParams> mWarnings;

                private readonly SourceStampVerificationStatus mSourceStampVerificationStatus;

                public SourceStampInfo(ApkSignerInfo result)
                {
                    mCertificates = result.certs;
                    mCertificateLineage = result.certificateLineage;
                    mErrors = ApkVerificationIssueAdapter.getIssuesFromVerificationIssues(
                        result.getErrors());
                    mWarnings = ApkVerificationIssueAdapter.getIssuesFromVerificationIssues(
                        result.getWarnings());
                    if (mErrors.Count == 0 && mWarnings.Count == 0)
                    {
                        mSourceStampVerificationStatus = SourceStampVerificationStatus.STAMP_VERIFIED;
                    }
                    else
                    {
                        mSourceStampVerificationStatus =
                            SourceStampVerificationStatus.STAMP_VERIFICATION_FAILED;
                    }
                }

                public SourceStampInfo(SourceStampVerificationStatus sourceStampVerificationStatus)
                {
                    mCertificates = new List<X509Certificate>();
                    mCertificateLineage = new List<X509Certificate>();
                    mErrors = new List<IssueWithParams>();
                    mWarnings = new List<IssueWithParams>();
                    mSourceStampVerificationStatus = sourceStampVerificationStatus;
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
             * Returns a list containing all of the certificates in the stamp certificate lineage.
             */
                public List<X509Certificate> getCertificatesInLineage()
                {
                    return mCertificateLineage;
                }

                public bool containsErrors()
                {
                    return mErrors.Count != 0;
                }

                public List<IssueWithParams> getErrors()
                {
                    return mErrors;
                }

                public List<IssueWithParams> getWarnings()
                {
                    return mWarnings;
                }

                /**
             * Returns the reason for any source stamp verification failures, or {@code
             * STAMP_VERIFIED} if the source stamp was successfully verified.
             */
                public SourceStampVerificationStatus getSourceStampVerificationStatus()
                {
                    return mSourceStampVerificationStatus;
                }
            }
        }

        /**
         * Error or warning encountered while verifying an APK's signatures.
         */
        public enum Issue
        {
            /**
             * APK is not JAR-signed.
             */
            [Description("No JAR signatures")] JAR_SIG_NO_SIGNATURES,

            /**
             * APK does not contain any entries covered by JAR signatures.
             */
            [Description("No JAR entries covered by JAR signatures")]
            JAR_SIG_NO_SIGNED_ZIP_ENTRIES,

            /**
             * APK contains multiple entries with the same name.
             *
             * <ul>
             * <li>Parameter 1: name ({@code String})</li>
             * </ul>
             */
            [Description("Duplicate entry: {0}")] JAR_SIG_DUPLICATE_ZIP_ENTRY,

            /**
             * JAR manifest contains a section with a duplicate name.
             *
             * <ul>
             * <li>Parameter 1: section name ({@code String})</li>
             * </ul>
             */
            [Description("Duplicate section in META-INF/MANIFEST.MF: {0}")]
            JAR_SIG_DUPLICATE_MANIFEST_SECTION,

            /**
             * JAR manifest contains a section without a name.
             *
             * <ul>
             * <li>Parameter 1: section index (1-based) ({@code int})</li>
             * </ul>
             */
            [Description("Malformed META-INF/MANIFEST.MF: invidual section #{0} does not have a name")]
            JAR_SIG_UNNNAMED_MANIFEST_SECTION,

            /**
             * JAR signature file contains a section without a name.
             *
             * <ul>
             * <li>Parameter 1: signature file name ({@code String})</li>
             * <li>Parameter 2: section index (1-based) ({@code int})</li>
             * </ul>
             */
            [Description("Malformed {0}: invidual section #{1} does not have a name")]
            JAR_SIG_UNNNAMED_SIG_FILE_SECTION,

            /** APK is missing the JAR manifest entry (META-INF/MANIFEST.MF). */
            [Description("Missing META-INF/MANIFEST.MF")]
            JAR_SIG_NO_MANIFEST,

            /**
             * JAR manifest references an entry which is not there in the APK.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * </ul>
             */
            [Description("{0} entry referenced by META-INF/MANIFEST.MF not found in the APK")]
            JAR_SIG_MISSING_ZIP_ENTRY_REFERENCED_IN_MANIFEST,

            /**
             * JAR manifest does not list a digest for the specified entry.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * </ul>
             */
            [Description("No digest for {0} in META-INF/MANIFEST.MF")]
            JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_MANIFEST,

            /**
             * JAR signature does not list a digest for the specified entry.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * <li>Parameter 2: signature file name ({@code String})</li>
             * </ul>
             */
            [Description("No digest for {0} in {1}")]
            JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_SIG_FILE,

            /**
             * The specified JAR entry is not covered by JAR signature.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * </ul>
             */
            [Description("{0} entry not signed")] JAR_SIG_ZIP_ENTRY_NOT_SIGNED,

            /**
             * JAR signature uses different set of signers to protect the two specified ZIP entries.
             *
             * <ul>
             * <li>Parameter 1: first entry name ({@code String})</li>
             * <li>Parameter 2: first entry signer names ({@code List<String>})</li>
             * <li>Parameter 3: second entry name ({@code String})</li>
             * <li>Parameter 4: second entry signer names ({@code List<String>})</li>
             * </ul>
             */
            [Description("Entries {0} and {2} are signed with different sets of signers : <{1}> vs <{3}>")]
            JAR_SIG_ZIP_ENTRY_SIGNERS_MISMATCH,

            /**
             * Digest of the specified ZIP entry's data does not match the digest expected by the JAR
             * signature.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * <li>Parameter 2: digest algorithm (e.g., SHA-256) ({@code String})</li>
             * <li>Parameter 3: name of the entry in which the expected digest is specified
             *     ({@code String})</li>
             * <li>Parameter 4: base64-encoded actual digest ({@code String})</li>
             * <li>Parameter 5: base64-encoded expected digest ({@code String})</li>
             * </ul>
             */
            [Description("{1} digest of {0} does not match the digest specified in {2}"
                         + ". Expected: <{4}>, actual: <{3}>")]
            JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY,

            /**
             * Digest of the JAR manifest main section did not verify.
             *
             * <ul>
             * <li>Parameter 1: digest algorithm (e.g., SHA-256) ({@code String})</li>
             * <li>Parameter 2: name of the entry in which the expected digest is specified
             *     ({@code String})</li>
             * <li>Parameter 3: base64-encoded actual digest ({@code String})</li>
             * <li>Parameter 4: base64-encoded expected digest ({@code String})</li>
             * </ul>
             */
            [Description("{0} digest of META-INF/MANIFEST.MF main section does not match the digest"
                         + " specified in {1}. Expected: <{3}>, actual: <{2}>")]
            JAR_SIG_MANIFEST_MAIN_SECTION_DIGEST_DID_NOT_VERIFY,

            /**
             * Digest of the specified JAR manifest section does not match the digest expected by the
             * JAR signature.
             *
             * <ul>
             * <li>Parameter 1: section name ({@code String})</li>
             * <li>Parameter 2: digest algorithm (e.g., SHA-256) ({@code String})</li>
             * <li>Parameter 3: name of the signature file in which the expected digest is specified
             *     ({@code String})</li>
             * <li>Parameter 4: base64-encoded actual digest ({@code String})</li>
             * <li>Parameter 5: base64-encoded expected digest ({@code String})</li>
             * </ul>
             */
            [Description("{1} digest of META-INF/MANIFEST.MF section for {0} does not match the digest"
                         + " specified in {2}. Expected: <{4}>, actual: <{3}>")]
            JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY,

            /**
             * JAR signature file does not contain the whole-file digest of the JAR manifest file. The
             * digest speeds up verification of JAR signature.
             *
             * <ul>
             * <li>Parameter 1: name of the signature file ({@code String})</li>
             * </ul>
             */
            [Description("{0} does not specify digest of META-INF/MANIFEST.MF"
                         + ". This slows down verification.")]
            JAR_SIG_NO_MANIFEST_DIGEST_IN_SIG_FILE,

            /**
             * APK is signed using APK Signature Scheme v2 or newer, but JAR signature file does not
             * contain protections against stripping of these newer scheme signatures.
             *
             * <ul>
             * <li>Parameter 1: name of the signature file ({@code String})</li>
             * </ul>
             */
            [Description("APK is signed using APK Signature Scheme v2 but these signatures may be stripped"
                         + " without being detected because {0} does not contain anti-stripping"
                         + " protections.")]
            JAR_SIG_NO_APK_SIG_STRIP_PROTECTION,

            /**
             * JAR signature of the signer is missing a file/entry.
             *
             * <ul>
             * <li>Parameter 1: name of the encountered file ({@code String})</li>
             * <li>Parameter 2: name of the missing file ({@code String})</li>
             * </ul>
             */
            [Description("Partial JAR signature. Found: {0}, missing: {1}")]
            JAR_SIG_MISSING_FILE,

            /**
             * An exception was encountered while verifying JAR signature contained in a signature block
             * against the signature file.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: name of the signature file ({@code String})</li>
             * <li>Parameter 3: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to verify JAR signature {0} against {1}: {2}")]
            JAR_SIG_VERIFY_EXCEPTION,

            /**
             * JAR signature contains unsupported digest algorithm.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: digest algorithm OID ({@code String})</li>
             * <li>Parameter 3: signature algorithm OID ({@code String})</li>
             * <li>Parameter 4: API Levels on which this combination of algorithms is not supported
             *     ({@code String})</li>
             * <li>Parameter 5: user-friendly variant of digest algorithm ({@code String})</li>
             * <li>Parameter 6: user-friendly variant of signature algorithm ({@code String})</li>
             * </ul>
             */
            [Description("JAR signature {0} uses digest algorithm {4} and signature algorithm {5} which"
                         + " is not supported on API Level(s) {3} for which this APK is being"
                         + " verified")]
            JAR_SIG_UNSUPPORTED_SIG_ALG,

            /**
             * An exception was encountered while parsing JAR signature contained in a signature block.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to parse JAR signature {0}: {1}")]
            JAR_SIG_PARSE_EXCEPTION,

            /**
             * An exception was encountered while parsing a certificate contained in the JAR signature
             * block.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed certificate in JAR signature {0}: {1}")]
            JAR_SIG_MALFORMED_CERTIFICATE,

            /**
             * JAR signature contained in a signature block file did not verify against the signature
             * file.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: name of the signature file ({@code String})</li>
             * </ul>
             */
            [Description("JAR signature {0} did not verify against {1}")]
            JAR_SIG_DID_NOT_VERIFY,

            /**
             * JAR signature contains no verified signers.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * </ul>
             */
            [Description("JAR signature {0} contains no signers")]
            JAR_SIG_NO_SIGNERS,

            /**
             * JAR signature file contains a section with a duplicate name.
             *
             * <ul>
             * <li>Parameter 1: signature file name ({@code String})</li>
             * <li>Parameter 1: section name ({@code String})</li>
             * </ul>
             */
            [Description("Duplicate section in {0}: {1}")]
            JAR_SIG_DUPLICATE_SIG_FILE_SECTION,

            /**
             * JAR signature file's main section doesn't contain the mandatory Signature-Version
             * attribute.
             *
             * <ul>
             * <li>Parameter 1: signature file name ({@code String})</li>
             * </ul>
             */
            [Description("Malformed {0}: missing Signature-Version attribute")]
            JAR_SIG_MISSING_VERSION_ATTR_IN_SIG_FILE,

            /**
             * JAR signature file references an unknown APK signature scheme ID.
             *
             * <ul>
             * <li>Parameter 1: name of the signature file ({@code String})</li>
             * <li>Parameter 2: unknown APK signature scheme ID ({@code} int)</li>
             * </ul>
             */
            [Description("JAR signature {0} references unknown APK signature scheme ID: {1}")]
            JAR_SIG_UNKNOWN_APK_SIG_SCHEME_ID,

            /**
             * JAR signature file indicates that the APK is supposed to be signed with a supported APK
             * signature scheme (in addition to the JAR signature) but no such signature was found in
             * the APK.
             *
             * <ul>
             * <li>Parameter 1: name of the signature file ({@code String})</li>
             * <li>Parameter 2: APK signature scheme ID ({@code} int)</li>
             * <li>Parameter 3: APK signature scheme English name ({@code} String)</li>
             * </ul>
             */
            [Description("JAR signature {0} indicates the APK is signed using {2} but no such signature"
                         + " was found. Signature stripped?")]
            JAR_SIG_MISSING_APK_SIG_REFERENCED,

            /**
             * JAR entry is not covered by signature and thus unauthorized modifications to its contents
             * will not be detected.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * </ul>
             */
            [Description("{0} not protected by signature. Unauthorized modifications to this JAR entry"
                         + " will not be detected. Delete or move the entry outside of META-INF/.")]
            JAR_SIG_UNPROTECTED_ZIP_ENTRY,

            /**
             * APK which is both JAR-signed and signed using APK Signature Scheme v2 contains an APK
             * Signature Scheme v2 signature from this signer, but does not contain a JAR signature
             * from this signer.
             */
            [Description("No JAR signature from this signer")]
            JAR_SIG_MISSING,

            /**
             * APK is targeting a sandbox version which requires APK Signature Scheme v2 signature but
             * no such signature was found.
             *
             * <ul>
             * <li>Parameter 1: target sandbox version ({@code int})</li>
             * </ul>
             */
            [Description("Missing APK Signature Scheme v2 signature required for target sandbox version"
                         + " {0}")]
            NO_SIG_FOR_TARGET_SANDBOX_VERSION,

            /**
             * APK is targeting an SDK version that requires a minimum signature scheme version, but the
             * APK is not signed with that version or later.
             *
             * <ul>
             *     <li>Parameter 1: target SDK Version (@code int})</li>
             *     <li>Parameter 2: minimum signature scheme version ((@code int})</li>
             * </ul>
             */
            [Description("Target SDK version {0} requires a minimum of signature scheme v{1}; the APK is"
                         + " not signed with this or a later signature scheme")]
            MIN_SIG_SCHEME_FOR_TARGET_SDK_NOT_MET,

            /**
             * APK which is both JAR-signed and signed using APK Signature Scheme v2 contains a JAR
             * signature from this signer, but does not contain an APK Signature Scheme v2 signature
             * from this signer.
             */
            [Description("No APK Signature Scheme v2 signature from this signer")]
            V2_SIG_MISSING,

            /**
             * Failed to parse the list of signers contained in the APK Signature Scheme v2 signature.
             */
            [Description("Malformed list of signers")]
            V2_SIG_MALFORMED_SIGNERS,

            /**
             * Failed to parse this signer's signer block contained in the APK Signature Scheme v2
             * signature.
             */
            [Description("Malformed signer block")]
            V2_SIG_MALFORMED_SIGNER,

            /**
             * Public key embedded in the APK Signature Scheme v2 signature of this signer could not be
             * parsed.
             *
             * <ul>
             * <li>Parameter 1: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed public key: {0}")]
            V2_SIG_MALFORMED_PUBLIC_KEY,

            /**
             * This APK Signature Scheme v2 signer's certificate could not be parsed.
             *
             * <ul>
             * <li>Parameter 1: index ({@code 0}-based) of the certificate in the signer's list of
             *     certificates ({@code int})</li>
             * <li>Parameter 2: sequence number ({@code 1}-based) of the certificate in the signer's
             *     list of certificates ({@code int})</li>
             * <li>Parameter 3: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed certificate #{1}: {2}")]
            V2_SIG_MALFORMED_CERTIFICATE,

            /**
             * Failed to parse this signer's signature record contained in the APK Signature Scheme v2
             * signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code int})</li>
             * </ul>
             */
            [Description("Malformed APK Signature Scheme v2 signature record #{0}")]
            V2_SIG_MALFORMED_SIGNATURE,

            /**
             * Failed to parse this signer's digest record contained in the APK Signature Scheme v2
             * signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code int})</li>
             * </ul>
             */
            [Description("Malformed APK Signature Scheme v2 digest record #{0}")]
            V2_SIG_MALFORMED_DIGEST,

            /**
             * This APK Signature Scheme v2 signer contains a malformed additional attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute number (first attribute is {@code 1}) {@code int})</li>
             * </ul>
             */
            [Description("Malformed additional attribute #{0}")]
            V2_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE,

            /**
             * APK Signature Scheme v2 signature references an unknown APK signature scheme ID.
             *
             * <ul>
             * <li>Parameter 1: signer index ({@code int})</li>
             * <li>Parameter 2: unknown APK signature scheme ID ({@code} int)</li>
             * </ul>
             */
            [Description("APK Signature Scheme v2 signer: {0} references unknown APK signature scheme ID: "
                         + "{1}")]
            V2_SIG_UNKNOWN_APK_SIG_SCHEME_ID,

            /**
             * APK Signature Scheme v2 signature indicates that the APK is supposed to be signed with a
             * supported APK signature scheme (in addition to the v2 signature) but no such signature
             * was found in the APK.
             *
             * <ul>
             * <li>Parameter 1: signer index ({@code int})</li>
             * <li>Parameter 2: APK signature scheme English name ({@code} String)</li>
             * </ul>
             */
            [Description("APK Signature Scheme v2 signature {0} indicates the APK is signed using {1} but "
                         + "no such signature was found. Signature stripped?")]
            V2_SIG_MISSING_APK_SIG_REFERENCED,

            /**
             * APK Signature Scheme v2 signature contains no signers.
             */
            [Description("No signers in APK Signature Scheme v2 signature")]
            V2_SIG_NO_SIGNERS,

            /**
             * This APK Signature Scheme v2 signer contains a signature produced using an unknown
             * algorithm.
             *
             * <ul>
             * <li>Parameter 1: algorithm ID ({@code int})</li>
             * </ul>
             */
            [Description("Unknown signature algorithm: %1$#x")]
            V2_SIG_UNKNOWN_SIG_ALGORITHM,

            /**
             * This APK Signature Scheme v2 signer contains an unknown additional attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute ID ({@code int})</li>
             * </ul>
             */
            [Description("Unknown additional attribute: ID %1$#x")]
            V2_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE,

            /**
             * An exception was encountered while verifying APK Signature Scheme v2 signature of this
             * signer.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to verify {0} signature: {1}")]
            V2_SIG_VERIFY_EXCEPTION,

            /**
             * APK Signature Scheme v2 signature over this signer's signed-data block did not verify.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * </ul>
             */
            [Description("{0} signature over signed-data did not verify")]
            V2_SIG_DID_NOT_VERIFY,

            /**
             * This APK Signature Scheme v2 signer offers no signatures.
             */
            [Description("No signatures")] V2_SIG_NO_SIGNATURES,

            /**
             * This APK Signature Scheme v2 signer offers signatures but none of them are supported.
             */
            [Description("No supported signatures: {0}")]
            V2_SIG_NO_SUPPORTED_SIGNATURES,

            /**
             * This APK Signature Scheme v2 signer offers no certificates.
             */
            [Description("No certificates")] V2_SIG_NO_CERTIFICATES,

            /**
             * This APK Signature Scheme v2 signer's public key listed in the signer's certificate does
             * not match the public key listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: hex-encoded public key from certificate ({@code String})</li>
             * <li>Parameter 2: hex-encoded public key from signatures record ({@code String})</li>
             * </ul>
             */
            [Description("Public key mismatch between certificate and signature record: <{0}> vs <{1}>")]
            V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,

            /**
             * This APK Signature Scheme v2 signer's signature algorithms listed in the signatures
             * record do not match the signature algorithms listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: signature algorithms from signatures record ({@code List<int>})</li>
             * <li>Parameter 2: signature algorithms from digests record ({@code List<int>})</li>
             * </ul>
             */
            [Description("Signature algorithms mismatch between signatures and digests records"
                         + ": {0} vs {1}")]
            V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS,

            /**
             * The APK's digest does not match the digest contained in the APK Signature Scheme v2
             * signature.
             *
             * <ul>
             * <li>Parameter 1: content digest algorithm ({@link ContentDigestAlgorithm})</li>
             * <li>Parameter 2: hex-encoded expected digest of the APK ({@code String})</li>
             * <li>Parameter 3: hex-encoded actual digest of the APK ({@code String})</li>
             * </ul>
             */
            [Description("APK integrity check failed. {0} digest mismatch."
                         + " Expected: <{1}>, actual: <{2}>")]
            V2_SIG_APK_DIGEST_DID_NOT_VERIFY,

            /**
             * Failed to parse the list of signers contained in the APK Signature Scheme v3 signature.
             */
            [Description("Malformed list of signers")]
            V3_SIG_MALFORMED_SIGNERS,

            /**
             * Failed to parse this signer's signer block contained in the APK Signature Scheme v3
             * signature.
             */
            [Description("Malformed signer block")]
            V3_SIG_MALFORMED_SIGNER,

            /**
             * Public key embedded in the APK Signature Scheme v3 signature of this signer could not be
             * parsed.
             *
             * <ul>
             * <li>Parameter 1: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed public key: {0}")]
            V3_SIG_MALFORMED_PUBLIC_KEY,

            /**
             * This APK Signature Scheme v3 signer's certificate could not be parsed.
             *
             * <ul>
             * <li>Parameter 1: index ({@code 0}-based) of the certificate in the signer's list of
             *     certificates ({@code int})</li>
             * <li>Parameter 2: sequence number ({@code 1}-based) of the certificate in the signer's
             *     list of certificates ({@code int})</li>
             * <li>Parameter 3: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed certificate #{1}: {2}")]
            V3_SIG_MALFORMED_CERTIFICATE,

            /**
             * Failed to parse this signer's signature record contained in the APK Signature Scheme v3
             * signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code int})</li>
             * </ul>
             */
            [Description("Malformed APK Signature Scheme v3 signature record #{0}")]
            V3_SIG_MALFORMED_SIGNATURE,

            /**
             * Failed to parse this signer's digest record contained in the APK Signature Scheme v3
             * signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code int})</li>
             * </ul>
             */
            [Description("Malformed APK Signature Scheme v3 digest record #{0}")]
            V3_SIG_MALFORMED_DIGEST,

            /**
             * This APK Signature Scheme v3 signer contains a malformed additional attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute number (first attribute is {@code 1}) {@code int})</li>
             * </ul>
             */
            [Description("Malformed additional attribute #{0}")]
            V3_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE,

            /**
             * APK Signature Scheme v3 signature contains no signers.
             */
            [Description("No signers in APK Signature Scheme v3 signature")]
            V3_SIG_NO_SIGNERS,

            /**
             * APK Signature Scheme v3 signature contains multiple signers (only one allowed per
             * platform version).
             */
            [Description("Multiple APK Signature Scheme v3 signatures found for a single "
                         + " platform version.")]
            V3_SIG_MULTIPLE_SIGNERS,

            /**
             * APK Signature Scheme v3 signature found, but multiple v1 and/or multiple v2 signers
             * found, where only one may be used with APK Signature Scheme v3
             */
            [Description("Multiple signatures found for pre-v3 signing with an APK "
                         + " Signature Scheme v3 signer.  Only one allowed.")]
            V3_SIG_MULTIPLE_PAST_SIGNERS,

            /**
             * APK Signature Scheme v3 signature found, but its signer doesn't match the v1/v2 signers,
             * or have them as the root of its signing certificate history
             */
            [Description("v3 signer differs from v1/v2 signer without proper signing certificate lineage.")]
            V3_SIG_PAST_SIGNERS_MISMATCH,

            /**
             * This APK Signature Scheme v3 signer contains a signature produced using an unknown
             * algorithm.
             *
             * <ul>
             * <li>Parameter 1: algorithm ID ({@code int})</li>
             * </ul>
             */
            [Description("Unknown signature algorithm: %1$#x")]
            V3_SIG_UNKNOWN_SIG_ALGORITHM,

            /**
             * This APK Signature Scheme v3 signer contains an unknown additional attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute ID ({@code int})</li>
             * </ul>
             */
            [Description("Unknown additional attribute: ID %1$#x")]
            V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE,

            /**
             * An exception was encountered while verifying APK Signature Scheme v3 signature of this
             * signer.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to verify {0} signature: {1}")]
            V3_SIG_VERIFY_EXCEPTION,

            /**
             * The APK Signature Scheme v3 signer contained an invalid value for either min or max SDK
             * versions.
             *
             * <ul>
             * <li>Parameter 1: minSdkVersion ({@code int})
             * <li>Parameter 2: maxSdkVersion ({@code int})
             * </ul>
             */
            [Description("Invalid SDK Version parameter(s) encountered in APK Signature "
                         + "scheme v3 signature: minSdkVersion {0} maxSdkVersion: {1}")]
            V3_SIG_INVALID_SDK_VERSIONS,

            /**
             * APK Signature Scheme v3 signature over this signer's signed-data block did not verify.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * </ul>
             */
            [Description("{0} signature over signed-data did not verify")]
            V3_SIG_DID_NOT_VERIFY,

            /**
             * This APK Signature Scheme v3 signer offers no signatures.
             */
            [Description("No signatures")] V3_SIG_NO_SIGNATURES,

            /**
             * This APK Signature Scheme v3 signer offers signatures but none of them are supported.
             */
            [Description("No supported signatures")]
            V3_SIG_NO_SUPPORTED_SIGNATURES,

            /**
             * This APK Signature Scheme v3 signer offers no certificates.
             */
            [Description("No certificates")] V3_SIG_NO_CERTIFICATES,

            /**
             * This APK Signature Scheme v3 signer's minSdkVersion listed in the signer's signed data
             * does not match the minSdkVersion listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: minSdkVersion in signature record ({@code int}) </li>
             * <li>Parameter 2: minSdkVersion in signed data ({@code int}) </li>
             * </ul>
             */
            [Description("minSdkVersion mismatch between signed data and signature record:"
                         + " <{0}> vs <{1}>")]
            V3_MIN_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD,

            /**
             * This APK Signature Scheme v3 signer's maxSdkVersion listed in the signer's signed data
             * does not match the maxSdkVersion listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: maxSdkVersion in signature record ({@code int}) </li>
             * <li>Parameter 2: maxSdkVersion in signed data ({@code int}) </li>
             * </ul>
             */
            [Description("maxSdkVersion mismatch between signed data and signature record:"
                         + " <{0}> vs <{1}>")]
            V3_MAX_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD,

            /**
             * This APK Signature Scheme v3 signer's public key listed in the signer's certificate does
             * not match the public key listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: hex-encoded public key from certificate ({@code String})</li>
             * <li>Parameter 2: hex-encoded public key from signatures record ({@code String})</li>
             * </ul>
             */
            [Description("Public key mismatch between certificate and signature record: <{0}> vs <{1}>")]
            V3_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,

            /**
             * This APK Signature Scheme v3 signer's signature algorithms listed in the signatures
             * record do not match the signature algorithms listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: signature algorithms from signatures record ({@code List<int>})</li>
             * <li>Parameter 2: signature algorithms from digests record ({@code List<int>})</li>
             * </ul>
             */
            [Description("Signature algorithms mismatch between signatures and digests records"
                         + ": {0} vs {1}")]
            V3_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS,

            /**
             * The APK's digest does not match the digest contained in the APK Signature Scheme v3
             * signature.
             *
             * <ul>
             * <li>Parameter 1: content digest algorithm ({@link ContentDigestAlgorithm})</li>
             * <li>Parameter 2: hex-encoded expected digest of the APK ({@code String})</li>
             * <li>Parameter 3: hex-encoded actual digest of the APK ({@code String})</li>
             * </ul>
             */
            [Description("APK integrity check failed. {0} digest mismatch."
                         + " Expected: <{1}>, actual: <{2}>")]
            V3_SIG_APK_DIGEST_DID_NOT_VERIFY,

            /**
             * The signer's SigningCertificateLineage attribute containd a proof-of-rotation record with
             * signature(s) that did not verify.
             */
            [Description("SigningCertificateLineage attribute containd a proof-of-rotation"
                         + " record with signature(s) that did not verify.")]
            V3_SIG_POR_DID_NOT_VERIFY,

            /**
             * Failed to parse the SigningCertificateLineage structure in the APK Signature Scheme v3
             * signature's additional attributes section.
             */
            [Description("Failed to parse the SigningCertificateLineage structure in the "
                         + "APK Signature Scheme v3 signature's additional attributes section.")]
            V3_SIG_MALFORMED_LINEAGE,

            /**
             * The APK's signing certificate does not match the terminal node in the provided
             * proof-of-rotation structure describing the signing certificate history
             */
            [Description("APK signing certificate differs from the associated certificate found in the "
                         + "signer's SigningCertificateLineage.")]
            V3_SIG_POR_CERT_MISMATCH,

            /**
             * The APK Signature Scheme v3 signers encountered do not offer a continuous set of
             * supported platform versions.  Either they overlap, resulting in potentially two
             * acceptable signers for a platform version, or there are holes which would create problems
             * in the event of platform version upgrades.
             */
            [Description("APK Signature Scheme v3 signers supported min/max SDK "
                         + "versions are not continuous.")]
            V3_INCONSISTENT_SDK_VERSIONS,

            /**
             * The APK Signature Scheme v3 signers don't cover all requested SDK versions.
             *
             *  <ul>
             * <li>Parameter 1: minSdkVersion ({@code int})
             * <li>Parameter 2: maxSdkVersion ({@code int})
             * </ul>
             */
            [Description("APK Signature Scheme v3 signers supported min/max SDK "
                         + "versions do not cover the entire desired range.  Found min:  {0} max {1}")]
            V3_MISSING_SDK_VERSIONS,

            /**
             * The SigningCertificateLineages for different platform versions using APK Signature Scheme
             * v3 do not go together.  Specifically, each should be a subset of another, with the size
             * of each increasing as the platform level increases.
             */
            [Description("SigningCertificateLineages targeting different platform versions"
                         + " using APK Signature Scheme v3 are not all a part of the same overall lineage.")]
            V3_INCONSISTENT_LINEAGES,

            /**
             * APK Signing Block contains an unknown entry.
             *
             * <ul>
             * <li>Parameter 1: entry ID ({@code int})</li>
             * </ul>
             */
            [Description("APK Signing Block contains unknown entry: ID %1$#x")]
            APK_SIG_BLOCK_UNKNOWN_ENTRY_ID,

            /**
             * Failed to parse this signer's signature record contained in the APK Signature Scheme
             * V4 signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code int})</li>
             * </ul>
             */
            [Description("V4 signature has malformed signer block")]
            V4_SIG_MALFORMED_SIGNERS,

            /**
             * This APK Signature Scheme V4 signer contains a signature produced using an
             * unknown algorithm.
             *
             * <ul>
             * <li>Parameter 1: algorithm ID ({@code int})</li>
             * </ul>
             */
            [Description("V4 signature has unknown signing algorithm: %1$#x")]
            V4_SIG_UNKNOWN_SIG_ALGORITHM,

            /**
             * This APK Signature Scheme V4 signer offers no signatures.
             */
            [Description("V4 signature has no signature found")]
            V4_SIG_NO_SIGNATURES,

            /**
             * This APK Signature Scheme V4 signer offers signatures but none of them are
             * supported.
             */
            [Description("V4 signature has no supported signature")]
            V4_SIG_NO_SUPPORTED_SIGNATURES,

            /**
             * APK Signature Scheme v3 signature over this signer's signed-data block did not verify.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * </ul>
             */
            [Description("{0} signature over signed-data did not verify")]
            V4_SIG_DID_NOT_VERIFY,

            /**
             * An exception was encountered while verifying APK Signature Scheme v3 signature of this
             * signer.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to verify {0} signature: {1}")]
            V4_SIG_VERIFY_EXCEPTION,

            /**
             * Public key embedded in the APK Signature Scheme v4 signature of this signer could not be
             * parsed.
             *
             * <ul>
             * <li>Parameter 1: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed public key: {0}")]
            V4_SIG_MALFORMED_PUBLIC_KEY,

            /**
             * This APK Signature Scheme V4 signer's certificate could not be parsed.
             *
             * <ul>
             * <li>Parameter 1: index ({@code 0}-based) of the certificate in the signer's list of
             *     certificates ({@code int})</li>
             * <li>Parameter 2: sequence number ({@code 1}-based) of the certificate in the signer's
             *     list of certificates ({@code int})</li>
             * <li>Parameter 3: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("V4 signature has malformed certificate")]
            V4_SIG_MALFORMED_CERTIFICATE,

            /**
             * This APK Signature Scheme V4 signer offers no certificate.
             */
            [Description("V4 signature has no certificate")]
            V4_SIG_NO_CERTIFICATE,

            /**
             * This APK Signature Scheme V4 signer's public key listed in the signer's
             * certificate does not match the public key listed in the signature proto.
             *
             * <ul>
             * <li>Parameter 1: hex-encoded public key from certificate ({@code String})</li>
             * <li>Parameter 2: hex-encoded public key from signature proto ({@code String})</li>
             * </ul>
             */
            [Description("V4 signature has mismatched certificate and signature: <{0}> vs <{1}>")]
            V4_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,

            /**
             * The APK's hash root (aka digest) does not match the hash root contained in the Signature
             * Scheme V4 signature.
             *
             * <ul>
             * <li>Parameter 1: content digest algorithm ({@link ContentDigestAlgorithm})</li>
             * <li>Parameter 2: hex-encoded expected digest of the APK ({@code String})</li>
             * <li>Parameter 3: hex-encoded actual digest of the APK ({@code String})</li>
             * </ul>
             */
            [Description("V4 signature's hash tree root (content digest) did not verity")]
            V4_SIG_APK_ROOT_DID_NOT_VERIFY,

            /**
             * The APK's hash tree does not match the hash tree contained in the Signature
             * Scheme V4 signature.
             *
             * <ul>
             * <li>Parameter 1: content digest algorithm ({@link ContentDigestAlgorithm})</li>
             * <li>Parameter 2: hex-encoded expected hash tree of the APK ({@code String})</li>
             * <li>Parameter 3: hex-encoded actual hash tree of the APK ({@code String})</li>
             * </ul>
             */
            [Description("V4 signature's hash tree did not verity")]
            V4_SIG_APK_TREE_DID_NOT_VERIFY,

            /**
             * Using more than one Signer to sign APK Signature Scheme V4 signature.
             */
            [Description("V4 signature only supports one signer")]
            V4_SIG_MULTIPLE_SIGNERS,

            /**
             * The signer used to sign APK Signature Scheme V2/V3 signature does not match the signer
             * used to sign APK Signature Scheme V4 signature.
             */
            [Description("V4 signature and V2/V3 signature have mismatched certificates")]
            V4_SIG_V2_V3_SIGNERS_MISMATCH,

            [Description("V4 signature and V2/V3 signature have mismatched digests")]
            V4_SIG_V2_V3_DIGESTS_MISMATCH,

            /**
             * The v4 signature format version isn't the same as the tool's current version, something
             * may go wrong.
             */
            [Description("V4 signature format version {0} is different from the tool's current "
                         + "version {1}")]
            V4_SIG_VERSION_NOT_CURRENT,

            /**
             * The APK does not contain the source stamp certificate digest file nor the signature block
             * when verification expected a source stamp to be present.
             */
            [Description("Neither the source stamp certificate digest file nor the signature block are "
                         + "present in the APK")]
            SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING,

            /** APK contains SourceStamp file, but does not contain a SourceStamp signature. */
            [Description("No SourceStamp signature")]
            SOURCE_STAMP_SIG_MISSING,

            /**
             * SourceStamp's certificate could not be parsed.
             *
             * <ul>
             *   <li>Parameter 1: error details ({@code Throwable})
             * </ul>
             */
            [Description("Malformed certificate: {0}")]
            SOURCE_STAMP_MALFORMED_CERTIFICATE,

            /** Failed to parse SourceStamp's signature. */
            [Description("Malformed SourceStamp signature")]
            SOURCE_STAMP_MALFORMED_SIGNATURE,

            /**
             * SourceStamp contains a signature produced using an unknown algorithm.
             *
             * <ul>
             *   <li>Parameter 1: algorithm ID ({@code int})
             * </ul>
             */
            [Description("Unknown signature algorithm: %1$#x")]
            SOURCE_STAMP_UNKNOWN_SIG_ALGORITHM,

            /**
             * An exception was encountered while verifying SourceStamp signature.
             *
             * <ul>
             *   <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})
             *   <li>Parameter 2: exception ({@code Throwable})
             * </ul>
             */
            [Description("Failed to verify {0} signature: {1}")]
            SOURCE_STAMP_VERIFY_EXCEPTION,

            /**
             * SourceStamp signature block did not verify.
             *
             * <ul>
             *   <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})
             * </ul>
             */
            [Description("{0} signature over signed-data did not verify")]
            SOURCE_STAMP_DID_NOT_VERIFY,

            /** SourceStamp offers no signatures. */
            [Description("No signature")] SOURCE_STAMP_NO_SIGNATURE,

            /**
             * SourceStamp offers an unsupported signature.
             * <ul>
             *     <li>Parameter 1: list of {@link SignatureAlgorithm}s  in the source stamp
             *     signing block.
             *     <li>Parameter 2: {@code Exception} caught when attempting to obtain the list of
             *     supported signatures.
             * </ul>
             */
            [Description("Signature(s) {{0}} not supported: {1}")]
            SOURCE_STAMP_NO_SUPPORTED_SIGNATURE,

            /**
             * SourceStamp's certificate listed in the APK signing block does not match the certificate
             * listed in the SourceStamp file in the APK.
             *
             * <ul>
             *   <li>Parameter 1: SHA-256 hash of certificate from SourceStamp block in APK signing
             *       block ({@code String})
             *   <li>Parameter 2: SHA-256 hash of certificate from SourceStamp file in APK ({@code
             *       String})
             * </ul>
             */
            [Description("Certificate mismatch between SourceStamp block in APK signing block and"
                         + " SourceStamp file in APK: <{0}> vs <{1}>")]
            SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK,

            /**
             * The APK contains a source stamp signature block without the expected certificate digest
             * in the APK contents.
             */
            [Description("A source stamp signature block was found without a corresponding certificate "
                         + "digest in the APK")]
            SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST,

            /**
             * When verifying just the source stamp, the certificate digest in the APK does not match
             * the expected digest.
             * <ul>
             *     <li>Parameter 1: SHA-256 digest of the source stamp certificate in the APK.
             *     <li>Parameter 2: SHA-256 digest of the expected source stamp certificate.
             * </ul>
             */
            [Description("The source stamp certificate digest in the APK, {0}, does not match the "
                         + "expected digest, {1}")]
            SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH,

            /**
             * Source stamp block contains a malformed attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute number (first attribute is {@code 1}) {@code int})</li>
             * </ul>
             */
            [Description("Malformed stamp attribute #{0}")]
            SOURCE_STAMP_MALFORMED_ATTRIBUTE,

            /**
             * Source stamp block contains an unknown attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute ID ({@code int})</li>
             * </ul>
             */
            [Description("Unknown stamp attribute: ID %1$#x")]
            SOURCE_STAMP_UNKNOWN_ATTRIBUTE,

            /**
             * Failed to parse the SigningCertificateLineage structure in the source stamp
             * attributes section.
             */
            [Description("Failed to parse the SigningCertificateLineage "
                         + "structure in the source stamp attributes section.")]
            SOURCE_STAMP_MALFORMED_LINEAGE,

            /**
             * The source stamp certificate does not match the terminal node in the provided
             * proof-of-rotation structure describing the stamp certificate history.
             */
            [Description("APK signing certificate differs from the associated certificate found in the "
                         + "signer's SigningCertificateLineage.")]
            SOURCE_STAMP_POR_CERT_MISMATCH,

            /**
             * The source stamp SigningCertificateLineage attribute contains a proof-of-rotation record
             * with signature(s) that did not verify.
             */
            [Description("Source stamp SigningCertificateLineage attribute "
                         + "contains a proof-of-rotation record with signature(s) that did not verify.")]
            SOURCE_STAMP_POR_DID_NOT_VERIFY,

            /**
             * The APK could not be properly parsed due to a ZIP or APK format exception.
             * <ul>
             *     <li>Parameter 1: The {@code Exception} caught when attempting to parse the APK.
             * </ul>
             */
            [Description("Malformed APK; the following exception was caught when attempting to parse the "
                         + "APK: {0}")]
            MALFORMED_APK,

            /**
             * An unexpected exception was caught when attempting to verify the signature(s) within the
             * APK.
             * <ul>
             *     <li>Parameter 1: The {@code Exception} caught during verification.
             * </ul>
             */
            [Description("An unexpected exception was caught when verifying the signature: {0}")]
            UNEXPECTED_EXCEPTION
        }

        /**
         * {@link Issue} with associated parameters. {@link #toString()} produces a readable formatted
         * form.
         */
        public class IssueWithParams : ApkVerificationIssue
        {
            private readonly Issue mIssue;
            private readonly Object[] mParams;

            /**
          * Constructs a new {@code IssueWithParams} of the specified type and with provided
          * parameters.
          */
            public IssueWithParams(Issue issue, Object[] parameters) : base(issue.getFormat(), parameters)
            {
                mIssue = issue;
                mParams = parameters;
            }

            /**
             * Returns the type of this issue.
             */
            public Issue getIssue()
            {
                return mIssue;
            }

            /**
             * Returns the parameters of this issue.
             */
            public override Object[] getParams()
            {
                return (object[])mParams.Clone();
            }

            /**
             * Returns a readable form of this issue.
             */
            public override String ToString()
            {
                return String.Format(mIssue.getFormat(), mParams);
            }
        }

        /**
     * Wrapped around {@code byte[]} which ensures that {@code equals} and {@code hashCode} operate
     * on the contents of the arrays rather than on references.
     */
        private class ByteArray
        {
            private readonly byte[] mArray;
            private readonly int mHashCode;

            public ByteArray(byte[] arr)
            {
                mArray = arr;
                mHashCode = mArray.GetHashCode();
            }

            public int hashCode()
            {
                return mHashCode;
            }

            public bool equals(Object obj)
            {
                if (this == obj)
                {
                    return true;
                }

                if (!(obj is ByteArray))
                {
                    return false;
                }

                ByteArray other = (ByteArray)obj;
                if (hashCode() != other.hashCode())
                {
                    return false;
                }

                if (!mArray.SequenceEqual(other.mArray))
                {
                    return false;
                }

                return true;
            }
        }

        /**
     * Builder of {@link ApkVerifier} instances.
     *
     * <p>The resulting verifier by default checks whether the APK will verify on all platform
     * versions supported by the APK, as specified by {@code android:minSdkVersion} attributes in
     * the APK's {@code AndroidManifest.xml}. The range of platform versions can be customized using
     * {@link #setMinCheckedPlatformVersion(int)} and {@link #setMaxCheckedPlatformVersion(int)}.
     */
        public class Builder
        {
            private readonly FileInfo mApkFile;
            private readonly DataSource mApkDataSource;
            private FileInfo mV4SignatureFile;

            private int mMinSdkVersion;
            private int mMaxSdkVersion = int.MaxValue;

            /**
         * Constructs a new {@code Builder} for verifying the provided APK file.
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
         * Constructs a new {@code Builder} for verifying the provided APK.
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
         * Sets the oldest Android platform version for which the APK is verified. APK verification
         * will confirm that the APK is expected to install successfully on all known Android
         * platforms starting from the platform version with the provided API Level. The upper end
         * of the platform versions range can be modified via
         * {@link #setMaxCheckedPlatformVersion(int)}.
         *
         * <p>This method is useful for overriding the default behavior which checks that the APK
         * will verify on all platform versions supported by the APK, as specified by
         * {@code android:minSdkVersion} attributes in the APK's {@code AndroidManifest.xml}.
         *
         * @param minSdkVersion API Level of the oldest platform for which to verify the APK
         * @see #setMinCheckedPlatformVersion(int)
         */
            public Builder setMinCheckedPlatformVersion(int minSdkVersion)
            {
                mMinSdkVersion = minSdkVersion;
                return this;
            }

            /**
         * Sets the newest Android platform version for which the APK is verified. APK verification
         * will confirm that the APK is expected to install successfully on all platform versions
         * supported by the APK up until and including the provided version. The lower end
         * of the platform versions range can be modified via
         * {@link #setMinCheckedPlatformVersion(int)}.
         *
         * @param maxSdkVersion API Level of the newest platform for which to verify the APK
         * @see #setMinCheckedPlatformVersion(int)
         */
            public Builder setMaxCheckedPlatformVersion(int maxSdkVersion)
            {
                mMaxSdkVersion = maxSdkVersion;
                return this;
            }

            public Builder setV4SignatureFile(FileInfo v4SignatureFile)
            {
                mV4SignatureFile = v4SignatureFile;
                return this;
            }

            /**
         * Returns an {@link ApkVerifier} initialized according to the configuration of this
         * builder.
         */
            public ApkVerifier build()
            {
                return new ApkVerifier(
                    mApkFile,
                    mApkDataSource,
                    mV4SignatureFile,
                    mMinSdkVersion,
                    mMaxSdkVersion);
            }
        }

        /**
     * Adapter for converting base {@link ApkVerificationIssue} instances to their {@link
     * IssueWithParams} equivalent.
     */
        public class ApkVerificationIssueAdapter
        {
            private ApkVerificationIssueAdapter()
            {
            }

            // This field is visible for testing
            public static readonly Dictionary<int, Issue> sVerificationIssueIdToIssue = new Dictionary<int, Issue>
            {
                [ApkVerificationIssue.V2_SIG_MALFORMED_SIGNERS] = Issue.V2_SIG_MALFORMED_SIGNERS,
                [ApkVerificationIssue.V2_SIG_NO_SIGNERS] = Issue.V2_SIG_NO_SIGNERS,
                [ApkVerificationIssue.V2_SIG_MALFORMED_SIGNER] = Issue.V2_SIG_MALFORMED_SIGNER,
                [ApkVerificationIssue.V2_SIG_MALFORMED_SIGNATURE] = Issue.V2_SIG_MALFORMED_SIGNATURE,
                [ApkVerificationIssue.V2_SIG_NO_SIGNATURES] = Issue.V2_SIG_NO_SIGNATURES,
                [ApkVerificationIssue.V2_SIG_MALFORMED_CERTIFICATE] = Issue.V2_SIG_MALFORMED_CERTIFICATE,
                [ApkVerificationIssue.V2_SIG_NO_CERTIFICATES] = Issue.V2_SIG_NO_CERTIFICATES,
                [ApkVerificationIssue.V2_SIG_MALFORMED_DIGEST] = Issue.V2_SIG_MALFORMED_DIGEST,
                [ApkVerificationIssue.V3_SIG_MALFORMED_SIGNERS] = Issue.V3_SIG_MALFORMED_SIGNERS,
                [ApkVerificationIssue.V3_SIG_NO_SIGNERS] = Issue.V3_SIG_NO_SIGNERS,
                [ApkVerificationIssue.V3_SIG_MALFORMED_SIGNER] = Issue.V3_SIG_MALFORMED_SIGNER,
                [ApkVerificationIssue.V3_SIG_MALFORMED_SIGNATURE] = Issue.V3_SIG_MALFORMED_SIGNATURE,
                [ApkVerificationIssue.V3_SIG_NO_SIGNATURES] = Issue.V3_SIG_NO_SIGNATURES,
                [ApkVerificationIssue.V3_SIG_MALFORMED_CERTIFICATE] = Issue.V3_SIG_MALFORMED_CERTIFICATE,
                [ApkVerificationIssue.V3_SIG_NO_CERTIFICATES] = Issue.V3_SIG_NO_CERTIFICATES,
                [ApkVerificationIssue.V3_SIG_MALFORMED_DIGEST] = Issue.V3_SIG_MALFORMED_DIGEST,
                [ApkVerificationIssue.SOURCE_STAMP_NO_SIGNATURE] = Issue.SOURCE_STAMP_NO_SIGNATURE,
                [ApkVerificationIssue.SOURCE_STAMP_MALFORMED_CERTIFICATE] = Issue.SOURCE_STAMP_MALFORMED_CERTIFICATE,
                [ApkVerificationIssue.SOURCE_STAMP_UNKNOWN_SIG_ALGORITHM] = Issue.SOURCE_STAMP_UNKNOWN_SIG_ALGORITHM,
                [ApkVerificationIssue.SOURCE_STAMP_MALFORMED_SIGNATURE] = Issue.SOURCE_STAMP_MALFORMED_SIGNATURE,
                [ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY] = Issue.SOURCE_STAMP_DID_NOT_VERIFY,
                [ApkVerificationIssue.SOURCE_STAMP_VERIFY_EXCEPTION] = Issue.SOURCE_STAMP_VERIFY_EXCEPTION,
                [ApkVerificationIssue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH] =
                    Issue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH,
                [ApkVerificationIssue.SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST] =
                    Issue.SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST,
                [ApkVerificationIssue.SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING] =
                    Issue.SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING,
                [ApkVerificationIssue.SOURCE_STAMP_NO_SUPPORTED_SIGNATURE] = Issue.SOURCE_STAMP_NO_SUPPORTED_SIGNATURE,
                [ApkVerificationIssue.SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK] =
                    Issue.SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK,
                [ApkVerificationIssue.MALFORMED_APK] = Issue.MALFORMED_APK,
                [ApkVerificationIssue.UNEXPECTED_EXCEPTION] = Issue.UNEXPECTED_EXCEPTION,
                [ApkVerificationIssue.SOURCE_STAMP_SIG_MISSING] = Issue.SOURCE_STAMP_SIG_MISSING,
                [ApkVerificationIssue.SOURCE_STAMP_MALFORMED_ATTRIBUTE] = Issue.SOURCE_STAMP_MALFORMED_ATTRIBUTE,
                [ApkVerificationIssue.SOURCE_STAMP_UNKNOWN_ATTRIBUTE] = Issue.SOURCE_STAMP_UNKNOWN_ATTRIBUTE,
                [ApkVerificationIssue.SOURCE_STAMP_MALFORMED_LINEAGE] = Issue.SOURCE_STAMP_MALFORMED_LINEAGE,
                [ApkVerificationIssue.SOURCE_STAMP_POR_CERT_MISMATCH] = Issue.SOURCE_STAMP_POR_CERT_MISMATCH,
                [ApkVerificationIssue.SOURCE_STAMP_POR_DID_NOT_VERIFY] = Issue.SOURCE_STAMP_POR_DID_NOT_VERIFY,
                [ApkVerificationIssue.JAR_SIG_NO_SIGNATURES] = Issue.JAR_SIG_NO_SIGNATURES,
                [ApkVerificationIssue.JAR_SIG_PARSE_EXCEPTION] = Issue.JAR_SIG_PARSE_EXCEPTION,
            };

            /**
             * Converts the provided {@code verificationIssues} to a {@code List} of corresponding
             * {@link IssueWithParams} instances.
             */
            public static List<IssueWithParams> getIssuesFromVerificationIssues(
                List<ApkVerificationIssue> verificationIssues)
            {
                List<IssueWithParams> result = new List<IssueWithParams>(verificationIssues.Count);
                foreach (ApkVerificationIssue issue in verificationIssues)
                {
                    if (issue is IssueWithParams)
                    {
                        result.Add((IssueWithParams)issue);
                    }
                    else
                    {
                        result.Add(
                            new IssueWithParams(sVerificationIssueIdToIssue[issue.getIssueId()],
                                issue.getParams()));
                    }
                }

                return result;
            }
        }
    }

    public static class ApkVerifierIssueExtensions
    {
        /**
         * Returns the format string suitable for combining the parameters of this issue into a
         * readable string. See {@link java.util.Formatter} for format.
         */
        public static string getFormat(this ApkVerifier.Issue issue)
        {
            return typeof(ApkVerifier.Issue).GetField(issue.ToString())?.GetCustomAttribute<DescriptionAttribute>()
                ?.Description;
        }
    }
}