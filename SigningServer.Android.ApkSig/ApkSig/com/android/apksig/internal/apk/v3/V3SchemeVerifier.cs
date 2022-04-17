// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

/*
 * Copyright (C) 2022 Daniel Kuschny (C# port)
 * Copyright (C) 2018 The Android Open Source Project
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

namespace SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3
{
    /// <summary>
    /// APK Signature Scheme v3 verifier.
    /// 
    /// &lt;p&gt;APK Signature Scheme v3, like v2 is a whole-file signature scheme which aims to protect every
    /// single bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
    /// uncompressed contents of ZIP entries.
    /// 
    /// @see &lt;a href="https://source.android.com/security/apksigning/v2.html"&gt;APK Signature Scheme v2&lt;/a&gt;
    /// </summary>
    public abstract class V3SchemeVerifier
    {
        /// <summary>
        /// Hidden constructor to prevent instantiation.
        /// </summary>
        internal V3SchemeVerifier()
        {
        }
        
        /// <summary>
        /// Verifies the provided APK's APK Signature Scheme v3 signatures and returns the result of
        /// verification. The APK must be considered verified only if
        /// {@link ApkSigningBlockUtils.Result#verified} is
        /// {@code true}. If verification fails, the result will contain errors -- see
        /// {@link ApkSigningBlockUtils.Result#getErrors()}.
        /// 
        /// &lt;p&gt;Verification succeeds iff the APK's APK Signature Scheme v3 signatures are expected to
        /// verify on all Android platform versions in the {@code [minSdkVersion, maxSdkVersion]} range.
        /// If the APK's signature is expected to not verify on any of the specified platform versions,
        /// this method returns a result with one or more errors and whose
        /// {@code Result.verified == false}, or this method throws an exception.
        /// 
        /// @throws ApkFormatException if the APK is malformed
        /// @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
        ///         required cryptographic algorithm implementation is missing
        /// @throws SignatureNotFoundException if no APK Signature Scheme v3
        /// signatures are found
        /// @throws IOException if an I/O error occurs when reading the APK
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result Verify(SigningServer.Android.Com.Android.Apksig.Util.RunnablesExecutor executor, SigningServer.Android.Com.Android.Apksig.Util.DataSource apk, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ZipSections zipSections, int minSdkVersion, int maxSdkVersion)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result result = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureInfo signatureInfo = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.FindSignature(apk, zipSections, SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID, result);
            SigningServer.Android.Com.Android.Apksig.Util.DataSource beforeApkSigningBlock = apk.Slice(0, signatureInfo.apkSigningBlockOffset);
            SigningServer.Android.Com.Android.Apksig.Util.DataSource centralDir = apk.Slice(signatureInfo.centralDirOffset, signatureInfo.eocdOffset - signatureInfo.centralDirOffset);
            SigningServer.Android.IO.ByteBuffer eocd = signatureInfo.eocd;
            if (minSdkVersion < SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.P)
            {
                minSdkVersion = SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.P;
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeVerifier.Verify(
                executor
                , 
                beforeApkSigningBlock
                , 
                signatureInfo.signatureBlock
                , 
                centralDir
                , 
                eocd
                , 
                minSdkVersion
                , 
                maxSdkVersion
                , 
                result
            
            );
            return result;
        }
        
        /// <summary>
        /// Verifies the provided APK's v3 signatures and outputs the results into the provided
        /// {@code result}. APK is considered verified only if there are no errors reported in the
        /// {@code result}. See {@link #verify(RunnablesExecutor, DataSource, ApkUtils.ZipSections, int,
        /// int)} for more information about the contract of this method.
        /// 
        /// @param result result populated by this method with interesting information about the APK,
        ///        such as information about signers, and verification errors and warnings.
        /// </summary>
        internal static void Verify(SigningServer.Android.Com.Android.Apksig.Util.RunnablesExecutor executor, SigningServer.Android.Com.Android.Apksig.Util.DataSource beforeApkSigningBlock, SigningServer.Android.IO.ByteBuffer apkSignatureSchemeV3Block, SigningServer.Android.Com.Android.Apksig.Util.DataSource centralDir, SigningServer.Android.IO.ByteBuffer eocd, int minSdkVersion, int maxSdkVersion, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result result)
        {
            SigningServer.Android.Collections.Set<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm> contentDigestsToVerify = new SigningServer.Android.Collections.HashSet<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm>(1);
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeVerifier.ParseSigners(apkSignatureSchemeV3Block, contentDigestsToVerify, result);
            if (result.ContainsErrors())
            {
                return;
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.VerifyIntegrity(
                executor
                , 
                beforeApkSigningBlock
                , 
                centralDir
                , 
                eocd
                , 
                contentDigestsToVerify
                , 
                result
            
            );
            SigningServer.Android.Collections.SortedMap<int, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo> sortedSigners = new SigningServer.Android.Collections.TreeMap<int, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo>();
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo signer in result.signers)
            {
                sortedSigners.Put(signer.minSdkVersion, signer);
            }
            int firstMin = 0;
            int lastMax = 0;
            int lastLineageSize = 0;
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.SigningCertificateLineage> lineages = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.SigningCertificateLineage>(result.signers.Size());
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo signer in sortedSigners.Values())
            {
                int currentMin = signer.minSdkVersion;
                int currentMax = signer.maxSdkVersion;
                if (firstMin == 0)
                {
                    firstMin = currentMin;
                }
                else 
                {
                    if (currentMin != lastMax + 1)
                    {
                        result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_INCONSISTENT_SDK_VERSIONS);
                        break;
                    }
                }
                lastMax = currentMax;
                if (signer.signingCertificateLineage != null)
                {
                    int currLineageSize = signer.signingCertificateLineage.Size();
                    if (currLineageSize < lastLineageSize)
                    {
                        result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_INCONSISTENT_LINEAGES);
                        break;
                    }
                    lastLineageSize = currLineageSize;
                    lineages.Add(signer.signingCertificateLineage);
                }
            }
            if (firstMin > minSdkVersion || lastMax < maxSdkVersion)
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_MISSING_SDK_VERSIONS, firstMin, lastMax);
            }
            try
            {
                result.signingCertificateLineage = SigningServer.Android.Com.Android.Apksig.SigningCertificateLineage.ConsolidateLineages(lineages);
            }
            catch (System.ArgumentException e)
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_INCONSISTENT_LINEAGES);
            }
            if (!result.ContainsErrors())
            {
                result.verified = true;
            }
        }
        
        /// <summary>
        /// Parses each signer in the provided APK Signature Scheme v3 block and populates corresponding
        /// {@code signerInfos} of the provided {@code result}.
        /// 
        /// &lt;p&gt;This verifies signatures over {@code signed-data} block contained in each signer block.
        /// However, this does not verify the integrity of the rest of the APK but rather simply reports
        /// the expected digests of the rest of the APK (see {@code contentDigestsToVerify}).
        /// 
        /// &lt;p&gt;This method adds one or more errors to the {@code result} if a verification error is
        /// expected to be encountered on an Android platform version in the
        /// {@code [minSdkVersion, maxSdkVersion]} range.
        /// </summary>
        public static void ParseSigners(SigningServer.Android.IO.ByteBuffer apkSignatureSchemeV3Block, SigningServer.Android.Collections.Set<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm> contentDigestsToVerify, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result result)
        {
            SigningServer.Android.IO.ByteBuffer signers;
            try
            {
                signers = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(apkSignatureSchemeV3Block);
            }
            catch (SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException e)
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_MALFORMED_SIGNERS);
                return;
            }
            if (!signers.HasRemaining())
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_NO_SIGNERS);
                return;
            }
            SigningServer.Android.Security.Cert.CertificateFactory certFactory;
            try
            {
                certFactory = SigningServer.Android.Security.Cert.CertificateFactory.GetInstance("X.509");
            }
            catch (SigningServer.Android.Security.Cert.CertificateException e)
            {
                throw new SigningServer.Android.Core.RuntimeException("Failed to obtain X.509 CertificateFactory", e);
            }
            int signerCount = 0;
            while (signers.HasRemaining())
            {
                int signerIndex = signerCount;
                signerCount++;
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo signerInfo = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo();
                signerInfo.index = signerIndex;
                result.signers.Add(signerInfo);
                try
                {
                    SigningServer.Android.IO.ByteBuffer signer = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(signers);
                    SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeVerifier.ParseSigner(signer, certFactory, signerInfo, contentDigestsToVerify);
                }
                catch (System.Exception e) when ( e is SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException || e is SigningServer.Android.IO.BufferUnderflowException)
                {
                    signerInfo.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_MALFORMED_SIGNER);
                    return;
                }
            }
        }
        
        /// <summary>
        /// Parses the provided signer block and populates the {@code result}.
        /// 
        /// &lt;p&gt;This verifies signatures over {@code signed-data} contained in this block, as well as
        /// the data contained therein, but does not verify the integrity of the rest of the APK. To
        /// facilitate APK integrity verification, this method adds the {@code contentDigestsToVerify}.
        /// These digests can then be used to verify the integrity of the APK.
        /// 
        /// &lt;p&gt;This method adds one or more errors to the {@code result} if a verification error is
        /// expected to be encountered on an Android platform version in the
        /// {@code [minSdkVersion, maxSdkVersion]} range.
        /// </summary>
        internal static void ParseSigner(SigningServer.Android.IO.ByteBuffer signerBlock, SigningServer.Android.Security.Cert.CertificateFactory certFactory, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo result, SigningServer.Android.Collections.Set<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm> contentDigestsToVerify)
        {
            SigningServer.Android.IO.ByteBuffer signedData = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(signerBlock);
            byte[] signedDataBytes = new byte[signedData.Remaining()];
            signedData.Get(signedDataBytes);
            signedData.Flip();
            result.signedData = signedDataBytes;
            int parsedMinSdkVersion = signerBlock.GetInt();
            int parsedMaxSdkVersion = signerBlock.GetInt();
            result.minSdkVersion = parsedMinSdkVersion;
            result.maxSdkVersion = parsedMaxSdkVersion;
            if (parsedMinSdkVersion < 0 || parsedMinSdkVersion > parsedMaxSdkVersion)
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_INVALID_SDK_VERSIONS, parsedMinSdkVersion, parsedMaxSdkVersion);
            }
            SigningServer.Android.IO.ByteBuffer signatures = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(signerBlock);
            byte[] publicKeyBytes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.ReadLengthPrefixedByteArray(signerBlock);
            int signatureCount = 0;
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SupportedSignature> supportedSignatures = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SupportedSignature>(1);
            while (signatures.HasRemaining())
            {
                signatureCount++;
                try
                {
                    SigningServer.Android.IO.ByteBuffer signature = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(signatures);
                    int sigAlgorithmId = signature.GetInt();
                    byte[] sigBytes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.ReadLengthPrefixedByteArray(signature);
                    result.signatures.Add(new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo.Signature(sigAlgorithmId, sigBytes));
                    SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm signatureAlgorithm = SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.FindById(sigAlgorithmId);
                    if (signatureAlgorithm == null)
                    {
                        result.AddWarning(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_UNKNOWN_SIG_ALGORITHM, sigAlgorithmId);
                        continue;
                    }
                    supportedSignatures.Add(new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SupportedSignature(signatureAlgorithm, sigBytes));
                }
                catch (System.Exception e) when ( e is SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException || e is SigningServer.Android.IO.BufferUnderflowException)
                {
                    result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_MALFORMED_SIGNATURE, signatureCount);
                    return;
                }
            }
            if (result.signatures.IsEmpty())
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_NO_SIGNATURES);
                return;
            }
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SupportedSignature> signaturesToVerify = null;
            try
            {
                signaturesToVerify = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetSignaturesToVerify(supportedSignatures, result.minSdkVersion, result.maxSdkVersion);
            }
            catch (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.NoSupportedSignaturesException e)
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_NO_SUPPORTED_SIGNATURES);
                return;
            }
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SupportedSignature signature in signaturesToVerify)
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm signatureAlgorithm = signature.algorithm;
                string jcaSignatureAlgorithm = signatureAlgorithm.GetJcaSignatureAlgorithmAndParams().GetFirst();
                SigningServer.Android.Security.Spec.AlgorithmParameterSpec jcaSignatureAlgorithmParams = signatureAlgorithm.GetJcaSignatureAlgorithmAndParams().GetSecond();
                string keyAlgorithm = signatureAlgorithm.GetJcaKeyAlgorithm();
                SigningServer.Android.Security.PublicKey publicKey;
                try
                {
                    publicKey = SigningServer.Android.Security.KeyFactory.GetInstance(keyAlgorithm).GeneratePublic(new SigningServer.Android.Security.Spec.X509EncodedKeySpec(publicKeyBytes));
                }
                catch (System.Exception e)
                {
                    result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_MALFORMED_PUBLIC_KEY, e);
                    return;
                }
                try
                {
                    SigningServer.Android.Security.Signature sig = SigningServer.Android.Security.Signature.GetInstance(jcaSignatureAlgorithm);
                    sig.InitVerify(publicKey);
                    if (jcaSignatureAlgorithmParams != null)
                    {
                        sig.SetParameter(jcaSignatureAlgorithmParams);
                    }
                    signedData.Position(0);
                    sig.Update(signedData);
                    byte[] sigBytes = signature.signature;
                    if (!sig.Verify(sigBytes))
                    {
                        result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_DID_NOT_VERIFY, signatureAlgorithm);
                        return;
                    }
                    result.verifiedSignatures.Put(signatureAlgorithm, sigBytes);
                    contentDigestsToVerify.Add(signatureAlgorithm.GetContentDigestAlgorithm());
                }
                catch (System.Exception e) when ( e is SigningServer.Android.Security.InvalidKeyException || e is SigningServer.Android.Security.InvalidAlgorithmParameterException || e is SigningServer.Android.Security.SignatureException)
                {
                    result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_VERIFY_EXCEPTION, signatureAlgorithm, e);
                    return;
                }
            }
            signedData.Position(0);
            SigningServer.Android.IO.ByteBuffer digests = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(signedData);
            SigningServer.Android.IO.ByteBuffer certificates = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(signedData);
            int signedMinSdkVersion = signedData.GetInt();
            if (signedMinSdkVersion != parsedMinSdkVersion)
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_MIN_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD, parsedMinSdkVersion, signedMinSdkVersion);
            }
            int signedMaxSdkVersion = signedData.GetInt();
            if (signedMaxSdkVersion != parsedMaxSdkVersion)
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_MAX_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD, parsedMaxSdkVersion, signedMaxSdkVersion);
            }
            SigningServer.Android.IO.ByteBuffer additionalAttributes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(signedData);
            int certificateIndex = -1;
            while (certificates.HasRemaining())
            {
                certificateIndex++;
                byte[] encodedCert = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.ReadLengthPrefixedByteArray(certificates);
                SigningServer.Android.Security.Cert.X509Certificate certificate;
                try
                {
                    certificate = SigningServer.Android.Com.Android.Apksig.Internal.Util.X509CertificateUtils.GenerateCertificate(encodedCert, certFactory);
                }
                catch (SigningServer.Android.Security.Cert.CertificateException e)
                {
                    result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_MALFORMED_CERTIFICATE, certificateIndex, certificateIndex + 1, e);
                    return;
                }
                certificate = new SigningServer.Android.Com.Android.Apksig.Internal.Util.GuaranteedEncodedFormX509Certificate(certificate, encodedCert);
                result.certs.Add(certificate);
            }
            if (result.certs.IsEmpty())
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_NO_CERTIFICATES);
                return;
            }
            SigningServer.Android.Security.Cert.X509Certificate mainCertificate = result.certs.Get(0);
            byte[] certificatePublicKeyBytes;
            try
            {
                certificatePublicKeyBytes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodePublicKey(mainCertificate.GetPublicKey());
            }
            catch (SigningServer.Android.Security.InvalidKeyException e)
            {
                Console.WriteLine("Caught an exception encoding the public key: " + e);
                e.PrintStackTrace();
                certificatePublicKeyBytes = mainCertificate.GetPublicKey().GetEncoded();
            }
            if (!SigningServer.Android.Collections.Arrays.Equals(publicKeyBytes, certificatePublicKeyBytes))
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.ToHex(certificatePublicKeyBytes), SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.ToHex(publicKeyBytes));
                return;
            }
            int digestCount = 0;
            while (digests.HasRemaining())
            {
                digestCount++;
                try
                {
                    SigningServer.Android.IO.ByteBuffer digest = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(digests);
                    int sigAlgorithmId = digest.GetInt();
                    byte[] digestBytes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.ReadLengthPrefixedByteArray(digest);
                    result.contentDigests.Add(new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(sigAlgorithmId, digestBytes));
                }
                catch (System.Exception e) when ( e is SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException || e is SigningServer.Android.IO.BufferUnderflowException)
                {
                    result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_MALFORMED_DIGEST, digestCount);
                    return;
                }
            }
            SigningServer.Android.Collections.List<int?> sigAlgsFromSignaturesRecord = new SigningServer.Android.Collections.List<int?>(result.signatures.Size());
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo.Signature signature in result.signatures)
            {
                sigAlgsFromSignaturesRecord.Add(signature.GetAlgorithmId());
            }
            SigningServer.Android.Collections.List<int?> sigAlgsFromDigestsRecord = new SigningServer.Android.Collections.List<int?>(result.contentDigests.Size());
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo.ContentDigest digest in result.contentDigests)
            {
                sigAlgsFromDigestsRecord.Add(digest.GetSignatureAlgorithmId());
            }
            if (!sigAlgsFromSignaturesRecord.Equals(sigAlgsFromDigestsRecord))
            {
                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS, sigAlgsFromSignaturesRecord, sigAlgsFromDigestsRecord);
                return;
            }
            int additionalAttributeCount = 0;
            while (additionalAttributes.HasRemaining())
            {
                additionalAttributeCount++;
                try
                {
                    SigningServer.Android.IO.ByteBuffer attribute = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(additionalAttributes);
                    int id = attribute.GetInt();
                    byte[] value = SigningServer.Android.Com.Android.Apksig.Internal.Util.ByteBufferUtils.ToByteArray(attribute);
                    result.additionalAttributes.Add(new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo.AdditionalAttribute(id, value));
                    if (id == SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeConstants.PROOF_OF_ROTATION_ATTR_ID)
                    {
                        try
                        {
                            result.signingCertificateLineage = SigningServer.Android.Com.Android.Apksig.SigningCertificateLineage.ReadFromV3AttributeValue(value);
                            SigningServer.Android.Com.Android.Apksig.SigningCertificateLineage subLineage = result.signingCertificateLineage.GetSubLineage(result.certs.Get(0));
                            if (result.signingCertificateLineage.Size() != subLineage.Size())
                            {
                                result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_POR_CERT_MISMATCH);
                            }
                        }
                        catch (SigningServer.Android.Core.SecurityException e)
                        {
                            result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_POR_DID_NOT_VERIFY);
                        }
                        catch (System.ArgumentException e)
                        {
                            result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_POR_CERT_MISMATCH);
                        }
                        catch (System.Exception e)
                        {
                            result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_MALFORMED_LINEAGE);
                        }
                    }
                    else 
                    {
                        result.AddWarning(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE, id);
                    }
                }
                catch (System.Exception e) when ( e is SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException || e is SigningServer.Android.IO.BufferUnderflowException)
                {
                    result.AddError(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.V3_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE, additionalAttributeCount);
                    return;
                }
            }
        }
        
    }
    
}
