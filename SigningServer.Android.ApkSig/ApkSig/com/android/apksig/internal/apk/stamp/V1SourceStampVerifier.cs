// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

/*
 * Copyright (C) 2022 Daniel Kuschny (C# port)
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

namespace SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp
{
    /// <summary>
    /// Source Stamp verifier.
    /// 
    /// &lt;p&gt;V1 of the source stamp verifies the stamp signature of at most one signature scheme.
    /// </summary>
    public abstract class V1SourceStampVerifier
    {
        /// <summary>
        /// Hidden constructor to prevent instantiation.
        /// </summary>
        internal V1SourceStampVerifier()
        {
        }
        
        /// <summary>
        /// Verifies the provided APK's SourceStamp signatures and returns the result of verification.
        /// The APK must be considered verified only if {@link ApkSigningBlockUtils.Result#verified} is
        /// {@code true}. If verification fails, the result will contain errors -- see {@link
        /// ApkSigningBlockUtils.Result#getErrors()}.
        /// 
        /// @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
        ///     required cryptographic algorithm implementation is missing
        /// @throws ApkSigningBlockUtils.SignatureNotFoundException if no SourceStamp signatures are
        ///     found
        /// @throws IOException if an I/O error occurs when reading the APK
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result Verify(SigningServer.Android.Com.Android.Apksig.Util.DataSource apk, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ZipSections zipSections, byte[] sourceStampCertificateDigest, SigningServer.Android.Collections.Map<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, byte[]> apkContentDigests, int minSdkVersion, int maxSdkVersion)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result result = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.VERSION_SOURCE_STAMP);
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureInfo signatureInfo = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.FindSignature(apk, zipSections, SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampConstants.V1_SOURCE_STAMP_BLOCK_ID, result);
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.V1SourceStampVerifier.Verify(
                signatureInfo.signatureBlock
                , 
                sourceStampCertificateDigest
                , 
                apkContentDigests
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
        /// Verifies the provided APK's SourceStamp signatures and outputs the results into the provided
        /// {@code result}. APK is considered verified only if there are no errors reported in the {@code
        /// result}. See {@link #verify(DataSource, ApkUtils.ZipSections, byte[], Map, int, int)} for
        /// more information about the contract of this method.
        /// </summary>
        internal static void Verify(SigningServer.Android.IO.ByteBuffer sourceStampBlock, byte[] sourceStampCertificateDigest, SigningServer.Android.Collections.Map<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, byte[]> apkContentDigests, int minSdkVersion, int maxSdkVersion, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result result)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo signerInfo = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.Result.SignerInfo();
            result.signers.Add(signerInfo);
            try
            {
                SigningServer.Android.Security.Cert.CertificateFactory certFactory = SigningServer.Android.Security.Cert.CertificateFactory.GetInstance("X.509");
                SigningServer.Android.IO.ByteBuffer sourceStampBlockData = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GetLengthPrefixedSlice(sourceStampBlock);
                byte[] digestBytes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.V1SourceStampVerifier.GetApkDigests(apkContentDigests));
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampVerifier.VerifyV1SourceStamp(
                    sourceStampBlockData
                    , 
                    certFactory
                    , 
                    signerInfo
                    , 
                    digestBytes
                    , 
                    sourceStampCertificateDigest
                    , 
                    minSdkVersion
                    , 
                    maxSdkVersion
                
                );
                result.verified = !result.ContainsErrors() && !result.ContainsWarnings();
            }
            catch (SigningServer.Android.Security.Cert.CertificateException e)
            {
                throw new System.InvalidOperationException("Failed to obtain X.509 CertificateFactory", e);
            }
            catch (System.Exception e) when ( e is SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException || e is SigningServer.Android.IO.BufferUnderflowException)
            {
                signerInfo.AddWarning(SigningServer.Android.Com.Android.Apksig.ApkVerifier.Issue.SOURCE_STAMP_MALFORMED_SIGNATURE);
            }
        }
        
        internal static SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int, byte[]>> GetApkDigests(SigningServer.Android.Collections.Map<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, byte[]> apkContentDigests)
        {
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int, byte[]>> digests = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int, byte[]>>();
            foreach (SigningServer.Android.Collections.MapEntry<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, byte[]> apkContentDigest in apkContentDigests.EntrySet())
            {
                digests.Add(SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<int, byte[]>(apkContentDigest.GetKey().GetId(), apkContentDigest.GetValue()));
            }

            SigningServer.Android.Util.Collections.Sort(digests, (a, b) => a.GetFirst().CompareTo(b.GetFirst()));
            return digests;
        }
        
    }
    
}
