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
using System.Linq;
using System.Reflection;
using SigningServer.Android.ApkSig.Internal.Util;

namespace SigningServer.Android.ApkSig.Internal.Apk
{
    /**
     * APK Signing Block signature algorithm.
     */
    public class SignatureAlgorithm
    {
        // TODO reserve the 0x0000 ID to mean null
        /**
     * RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc, content
     * digested using SHA2-256 in 1 MB chunks.
     */
        public static readonly SignatureAlgorithm RSA_PSS_WITH_SHA256 = new SignatureAlgorithm(
            0x0101,
            ContentDigestAlgorithm.CHUNKED_SHA256,
            "RSA",
            Tuple.Create("SHA256withRSA/PSS",
                (AlgorithmParameterSpec)new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1)),
            AndroidSdkVersion.N,
            AndroidSdkVersion.M);

        /**
     * RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc, content
     * digested using SHA2-512 in 1 MB chunks.
     */
        public static readonly SignatureAlgorithm RSA_PSS_WITH_SHA512 = new SignatureAlgorithm(
            0x0102,
            ContentDigestAlgorithm.CHUNKED_SHA512,
            "RSA",
            Tuple.Create(
                "SHA512withRSA/PSS",
                (AlgorithmParameterSpec)new PSSParameterSpec(
                    "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1)),
            AndroidSdkVersion.N,
            AndroidSdkVersion.M);

        /** RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks. */
        public static readonly SignatureAlgorithm RSA_PKCS1_V1_5_WITH_SHA256 = new SignatureAlgorithm(
            0x0103,
            ContentDigestAlgorithm.CHUNKED_SHA256,
            "RSA",
            Tuple.Create("SHA256withRSA", (AlgorithmParameterSpec)null),
            AndroidSdkVersion.N,
            AndroidSdkVersion.INITIAL_RELEASE);

        /** RSASSA-PKCS1-v1_5 with SHA2-512 digest, content digested using SHA2-512 in 1 MB chunks. */
        public static readonly SignatureAlgorithm RSA_PKCS1_V1_5_WITH_SHA512 = new SignatureAlgorithm(
            0x0104,
            ContentDigestAlgorithm.CHUNKED_SHA512,
            "RSA",
            Tuple.Create("SHA512withRSA", (AlgorithmParameterSpec)null),
            AndroidSdkVersion.N,
            AndroidSdkVersion.INITIAL_RELEASE);

        /** ECDSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks. */
        public static readonly SignatureAlgorithm ECDSA_WITH_SHA256 = new SignatureAlgorithm(
            0x0201,
            ContentDigestAlgorithm.CHUNKED_SHA256,
            "EC",
            Tuple.Create("SHA256withECDSA", (AlgorithmParameterSpec)null),
            AndroidSdkVersion.N,
            AndroidSdkVersion.HONEYCOMB);

        /** ECDSA with SHA2-512 digest, content digested using SHA2-512 in 1 MB chunks. */
        public static readonly SignatureAlgorithm ECDSA_WITH_SHA512 = new SignatureAlgorithm(
            0x0202,
            ContentDigestAlgorithm.CHUNKED_SHA512,
            "EC",
            Tuple.Create("SHA512withECDSA", (AlgorithmParameterSpec)null),
            AndroidSdkVersion.N,
            AndroidSdkVersion.HONEYCOMB);

        /** DSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks. */
        public static readonly SignatureAlgorithm DSA_WITH_SHA256 = new SignatureAlgorithm(
            0x0301,
            ContentDigestAlgorithm.CHUNKED_SHA256,
            "DSA",
            Tuple.Create("SHA256withDSA", (AlgorithmParameterSpec)null),
            AndroidSdkVersion.N,
            AndroidSdkVersion.INITIAL_RELEASE);

        /**
     * DSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks. Signing is done
     * deterministically according to RFC 6979.
     */
        public static readonly SignatureAlgorithm DETDSA_WITH_SHA256 = new SignatureAlgorithm(
            0x0301,
            ContentDigestAlgorithm.CHUNKED_SHA256,
            "DSA",
            Tuple.Create("SHA256withDetDSA", (AlgorithmParameterSpec)null),
            AndroidSdkVersion.N,
            AndroidSdkVersion.INITIAL_RELEASE);

        /**
     * RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 4 KB chunks, in
     * the same way fsverity operates. This digest and the content length (before digestion, 8 bytes
     * in little endian) construct the final digest.
     */
        public static readonly SignatureAlgorithm VERITY_RSA_PKCS1_V1_5_WITH_SHA256 = new SignatureAlgorithm(
            0x0421,
            ContentDigestAlgorithm.VERITY_CHUNKED_SHA256,
            "RSA",
            Tuple.Create("SHA256withRSA", (AlgorithmParameterSpec)null),
            AndroidSdkVersion.P,
            AndroidSdkVersion.INITIAL_RELEASE);

        /**
     * ECDSA with SHA2-256 digest, content digested using SHA2-256 in 4 KB chunks, in the same way
     * fsverity operates. This digest and the content length (before digestion, 8 bytes in little
     * endian) construct the final digest.
     */
        public static readonly SignatureAlgorithm VERITY_ECDSA_WITH_SHA256 = new SignatureAlgorithm(
            0x0423,
            ContentDigestAlgorithm.VERITY_CHUNKED_SHA256,
            "EC",
            Tuple.Create("SHA256withECDSA", (AlgorithmParameterSpec)null),
            AndroidSdkVersion.P,
            AndroidSdkVersion.HONEYCOMB);

        /**
     * DSA with SHA2-256 digest, content digested using SHA2-256 in 4 KB chunks, in the same way
     * fsverity operates. This digest and the content length (before digestion, 8 bytes in little
     * endian) construct the final digest.
     */
        public static readonly SignatureAlgorithm VERITY_DSA_WITH_SHA256 = new SignatureAlgorithm(
            0x0425,
            ContentDigestAlgorithm.VERITY_CHUNKED_SHA256,
            "DSA",
            Tuple.Create("SHA256withDSA", (AlgorithmParameterSpec)null),
            AndroidSdkVersion.P,
            AndroidSdkVersion.INITIAL_RELEASE);

        private readonly int mId;
        private readonly String mJcaKeyAlgorithm;
        private readonly ContentDigestAlgorithm mContentDigestAlgorithm;
        private readonly Tuple<String, AlgorithmParameterSpec> mJcaSignatureAlgAndParams;
        private readonly int mMinSdkVersion;
        private readonly int mJcaSigAlgMinSdkVersion;

        private SignatureAlgorithm(int id,
            ContentDigestAlgorithm contentDigestAlgorithm,
            String jcaKeyAlgorithm,
            Tuple<String, AlgorithmParameterSpec> jcaSignatureAlgAndParams,
            int minSdkVersion,
            int jcaSigAlgMinSdkVersion)
        {
            mId = id;
            mContentDigestAlgorithm = contentDigestAlgorithm;
            mJcaKeyAlgorithm = jcaKeyAlgorithm;
            mJcaSignatureAlgAndParams = jcaSignatureAlgAndParams;
            mMinSdkVersion = minSdkVersion;
            mJcaSigAlgMinSdkVersion = jcaSigAlgMinSdkVersion;
        }

        /**
         * Returns the ID of this signature algorithm as used in APK Signature Scheme v2 wire format.
         */
        public int getId()
        {
            return mId;
        }

        /**
         * Returns the content digest algorithm associated with this signature algorithm.
         */
        public ContentDigestAlgorithm getContentDigestAlgorithm()
        {
            return mContentDigestAlgorithm;
        }

        /**
     * Returns the JCA {@link java.security.Key} algorithm used by this signature scheme.
     */
        public String getJcaKeyAlgorithm()
        {
            return mJcaKeyAlgorithm;
        }

        /**
     * Returns the {@link java.security.Signature} algorithm and the {@link AlgorithmParameterSpec}
     * (or null if not needed) to parameterize the {@code Signature}.
     */
        public Tuple<String, AlgorithmParameterSpec> getJcaSignatureAlgorithmAndParams()
        {
            return mJcaSignatureAlgAndParams;
        }

        public int getMinSdkVersion()
        {
            return mMinSdkVersion;
        }

        /**
         * Returns the minimum SDK version that supports the JCA signature algorithm.
         */
        public int getJcaSigAlgMinSdkVersion()
        {
            return mJcaSigAlgMinSdkVersion;
        }

        private static IList<SignatureAlgorithm> mvalues;

        public static IList<SignatureAlgorithm> values()
        {
            if (mvalues == null)
            {
                mvalues = typeof(SignatureAlgorithm).GetFields(BindingFlags.Static | BindingFlags.Public)
                    .Where(f => f.FieldType == typeof(SignatureAlgorithm))
                    .Select(f => (SignatureAlgorithm)f.GetValue(null))
                    .ToList();
            }

            return mvalues;
        }

        public static SignatureAlgorithm findById(int id)
        {
            foreach (SignatureAlgorithm alg in SignatureAlgorithm.values())
            {
                if (alg.getId() == id)
                {
                    return alg;
                }
            }

            return null;
        }
    }
}