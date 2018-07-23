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

namespace SigningServer.Android.Crypto
{
    class SignatureAlgorithm
    {

        /** RSASSA-PKCS1-v1_5 with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks. */
        public static readonly SignatureAlgorithm RSA_PKCS1_V1_5_WITH_SHA256 = new SignatureAlgorithm(
            0x0103,
            ContentDigestAlgorithm.CHUNKED_SHA256,
            "RSA",
            DigestAlgorithm.SHA256);
        ///** RSASSA-PKCS1-v1_5 with SHA2-512 digest, content digested using SHA2-512 in 1 MB chunks. */
        public static readonly SignatureAlgorithm RSA_PKCS1_V1_5_WITH_SHA512 = new SignatureAlgorithm(
            0x0104,
            ContentDigestAlgorithm.CHUNKED_SHA512,
            "RSA",
            DigestAlgorithm.SHA512);

        /** DSA with SHA2-256 digest, content digested using SHA2-256 in 1 MB chunks. */
        public static readonly SignatureAlgorithm DSA_WITH_SHA256 = new SignatureAlgorithm(
            0x0301,
            ContentDigestAlgorithm.CHUNKED_SHA256,
            "DSA",
            DigestAlgorithm.SHA256);

        public int Id { get; set; }
        public string JcaKeyAlgorithm { get; set; }
        public ContentDigestAlgorithm ContentDigestAlgorithm { get; set; }
        public DigestAlgorithm DigestAlgorithm { get; set; }

        public SignatureAlgorithm(int id, ContentDigestAlgorithm contentDigestAlgorithm, string jcaKeyAlgorithm, DigestAlgorithm digestAlgorithm)
        {
            Id = id;
            JcaKeyAlgorithm = jcaKeyAlgorithm;
            ContentDigestAlgorithm = contentDigestAlgorithm;
            DigestAlgorithm = digestAlgorithm;
        }
    }
}