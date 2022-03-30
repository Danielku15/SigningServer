/*
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

using System.Collections.Generic;
using System.Numerics;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.ApkSig.Internal.Pkcs7;

namespace SigningServer.Android.ApkSig.Internal.X509
{
    /**
     * To Be Signed Certificate as specified in RFC 5280.
     */
    [Asn1Class(Type = Asn1Type.SEQUENCE)]
    public class TBSCertificate
    {
        [Asn1Field(
            Index = 0,
            Type = Asn1Type.INTEGER,
            Tagging = Asn1Tagging.EXPLICIT,
            TagNumber = 0)]
        public int version;

        [Asn1Field(Index = 1, Type = Asn1Type.INTEGER)]
        public BigInteger serialNumber;

        [Asn1Field(Index = 2, Type = Asn1Type.SEQUENCE)]
        public AlgorithmIdentifier signatureAlgorithm;

        [Asn1Field(Index = 3, Type = Asn1Type.CHOICE)]
        public Name issuer;

        [Asn1Field(Index = 4, Type = Asn1Type.SEQUENCE)]
        public Validity validity;

        [Asn1Field(Index = 5, Type = Asn1Type.CHOICE)]
        public Name subject;

        [Asn1Field(Index = 6, Type = Asn1Type.SEQUENCE)]
        public SubjectPublicKeyInfo subjectPublicKeyInfo;

        [Asn1Field(Index = 7,
            Type = Asn1Type.BIT_STRING,
            Tagging = Asn1Tagging.IMPLICIT,
            Optional = true,
            TagNumber = 1)]
        public ByteBuffer issuerUniqueID;

        [Asn1Field(Index = 8,
            Type = Asn1Type.BIT_STRING,
            Tagging = Asn1Tagging.IMPLICIT,
            Optional = true,
            TagNumber = 2)]
        public ByteBuffer subjectUniqueID;

        [Asn1Field(Index = 9,
            Type = Asn1Type.SEQUENCE_OF,
            Tagging = Asn1Tagging.EXPLICIT,
            Optional = true,
            TagNumber = 3)]
        public List<Extension> extensions;
    }
}