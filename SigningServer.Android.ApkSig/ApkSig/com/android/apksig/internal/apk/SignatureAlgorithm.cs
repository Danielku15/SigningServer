// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

/*
 * Copyright (C) 2022 Daniel Kuschny (C# port)
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
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Apk
{
    /// <summary>
    /// APK Signing Block signature algorithm.
    /// </summary>
    public class SignatureAlgorithm
    {
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm RSA_PSS_WITH_SHA256 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0101, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.CHUNKED_SHA256, "RSA", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA256withRSA/PSS", new SigningServer.Android.Security.Spec.PSSParameterSpec("SHA-256", "MGF1", SigningServer.Android.Security.Spec.MGF1ParameterSpec.SHA256, 256 / 8, 1)), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.N, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.M, 0);
        
        public const int RSA_PSS_WITH_SHA256_CASE = 0;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm RSA_PSS_WITH_SHA512 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0102, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.CHUNKED_SHA512, "RSA", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA512withRSA/PSS", new SigningServer.Android.Security.Spec.PSSParameterSpec("SHA-512", "MGF1", SigningServer.Android.Security.Spec.MGF1ParameterSpec.SHA512, 512 / 8, 1)), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.N, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.M, 1);
        
        public const int RSA_PSS_WITH_SHA512_CASE = 1;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm RSA_PKCS1_V1_5_WITH_SHA256 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0103, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.CHUNKED_SHA256, "RSA", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA256withRSA", null), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.N, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.INITIAL_RELEASE, 2);
        
        public const int RSA_PKCS1_V1_5_WITH_SHA256_CASE = 2;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm RSA_PKCS1_V1_5_WITH_SHA512 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0104, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.CHUNKED_SHA512, "RSA", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA512withRSA", null), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.N, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.INITIAL_RELEASE, 3);
        
        public const int RSA_PKCS1_V1_5_WITH_SHA512_CASE = 3;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm ECDSA_WITH_SHA256 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0201, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.CHUNKED_SHA256, "EC", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA256withECDSA", null), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.N, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.HONEYCOMB, 4);
        
        public const int ECDSA_WITH_SHA256_CASE = 4;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm ECDSA_WITH_SHA512 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0202, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.CHUNKED_SHA512, "EC", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA512withECDSA", null), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.N, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.HONEYCOMB, 5);
        
        public const int ECDSA_WITH_SHA512_CASE = 5;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm DSA_WITH_SHA256 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0301, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.CHUNKED_SHA256, "DSA", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA256withDSA", null), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.N, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.INITIAL_RELEASE, 6);
        
        public const int DSA_WITH_SHA256_CASE = 6;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm DETDSA_WITH_SHA256 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0301, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.CHUNKED_SHA256, "DSA", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA256withDetDSA", null), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.N, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.INITIAL_RELEASE, 7);
        
        public const int DETDSA_WITH_SHA256_CASE = 7;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm VERITY_RSA_PKCS1_V1_5_WITH_SHA256 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0421, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, "RSA", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA256withRSA", null), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.P, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.INITIAL_RELEASE, 8);
        
        public const int VERITY_RSA_PKCS1_V1_5_WITH_SHA256_CASE = 8;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm VERITY_ECDSA_WITH_SHA256 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0423, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, "EC", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA256withECDSA", null), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.P, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.HONEYCOMB, 9);
        
        public const int VERITY_ECDSA_WITH_SHA256_CASE = 9;
        
        public static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm VERITY_DSA_WITH_SHA256 = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm(0x0425, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, "DSA", SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, AlgorithmParameterSpec>("SHA256withDSA", null), SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.P, SigningServer.Android.Com.Android.Apksig.Internal.Util.AndroidSdkVersion.INITIAL_RELEASE, 10);
        
        public const int VERITY_DSA_WITH_SHA256_CASE = 10;
        
        internal readonly int mId;
        
        internal readonly string mJcaKeyAlgorithm;
        
        internal readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm mContentDigestAlgorithm;
        
        internal readonly SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<string, SigningServer.Android.Security.Spec.AlgorithmParameterSpec> mJcaSignatureAlgAndParams;
        
        internal readonly int mMinSdkVersion;
        
        internal readonly int mJcaSigAlgMinSdkVersion;
        
        internal SignatureAlgorithm(int id, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm contentDigestAlgorithm, string jcaKeyAlgorithm, SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<string, SigningServer.Android.Security.Spec.AlgorithmParameterSpec> jcaSignatureAlgAndParams, int minSdkVersion, int jcaSigAlgMinSdkVersion, int caseValue)
        {
            mId = id;
            mContentDigestAlgorithm = contentDigestAlgorithm;
            mJcaKeyAlgorithm = jcaKeyAlgorithm;
            mJcaSignatureAlgAndParams = jcaSignatureAlgAndParams;
            mMinSdkVersion = minSdkVersion;
            mJcaSigAlgMinSdkVersion = jcaSigAlgMinSdkVersion;
            Case = caseValue;
        }
        
        /// <summary>
        /// Returns the ID of this signature algorithm as used in APK Signature Scheme v2 wire format.
        /// </summary>
        public virtual int GetId()
        {
            return mId;
        }
        
        /// <summary>
        /// Returns the content digest algorithm associated with this signature algorithm.
        /// </summary>
        public virtual SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm GetContentDigestAlgorithm()
        {
            return mContentDigestAlgorithm;
        }
        
        /// <summary>
        /// Returns the JCA {@link java.security.Key} algorithm used by this signature scheme.
        /// </summary>
        public virtual string GetJcaKeyAlgorithm()
        {
            return mJcaKeyAlgorithm;
        }
        
        /// <summary>
        /// Returns the {@link java.security.Signature} algorithm and the {@link AlgorithmParameterSpec}
        /// (or null if not needed) to parameterize the {@code Signature}.
        /// </summary>
        public virtual SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<string, SigningServer.Android.Security.Spec.AlgorithmParameterSpec> GetJcaSignatureAlgorithmAndParams()
        {
            return mJcaSignatureAlgAndParams;
        }
        
        public virtual int GetMinSdkVersion()
        {
            return mMinSdkVersion;
        }
        
        /// <summary>
        /// Returns the minimum SDK version that supports the JCA signature algorithm.
        /// </summary>
        public virtual int GetJcaSigAlgMinSdkVersion()
        {
            return mJcaSigAlgMinSdkVersion;
        }
        
        public static SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm FindById(int id)
        {
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm alg in SignatureAlgorithm.Values())
            {
                if (alg.GetId() == id)
                {
                    return alg;
                }
            }
            return null;
        }
        
        int Case
        {
            get;
        }
        
        internal static readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm[] _values = {
        RSA_PSS_WITH_SHA256, 
        RSA_PSS_WITH_SHA512, 
        RSA_PKCS1_V1_5_WITH_SHA256, 
        RSA_PKCS1_V1_5_WITH_SHA512, 
        ECDSA_WITH_SHA256, 
        ECDSA_WITH_SHA512, 
        DSA_WITH_SHA256, 
        DETDSA_WITH_SHA256, 
        VERITY_RSA_PKCS1_V1_5_WITH_SHA256, 
        VERITY_ECDSA_WITH_SHA256, 
        VERITY_DSA_WITH_SHA256};
        
        public static SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm[] Values()
        {
            return _values;
        }
        
    }
    
}
