/*
 * Copyright (C) 2017 The Android Open Source Project
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
using SigningServer.Android.ApkSig.Internal.Asn1;

namespace SigningServer.Android.ApkSig.Internal.Pkcs7
{
    /**
     * PKCS #7 {@code SignerInfo} as specified in RFC 5652.
     */
    [Asn1Class(Type = Asn1Type.SEQUENCE)]
    public class SignerInfo
    {
        [Asn1Field(Index = 0, Type = Asn1Type.INTEGER)]
        public int version;

        [Asn1Field(Index = 1, Type = Asn1Type.CHOICE)]
        public SignerIdentifier sid;

        [Asn1Field(Index = 2, Type = Asn1Type.SEQUENCE)]
        public AlgorithmIdentifier digestAlgorithm;

        [Asn1Field(
            Index = 3,
            Type = Asn1Type.SET_OF,
            Tagging = Asn1Tagging.IMPLICIT,
            TagNumber = 0,
            Optional = true)]
        public Asn1OpaqueObject signedAttrs;

        [Asn1Field(Index = 4, Type = Asn1Type.SEQUENCE)]
        public AlgorithmIdentifier signatureAlgorithm;

        [Asn1Field(Index = 5, Type = Asn1Type.OCTET_STRING)]
        public ByteBuffer signature;

        [Asn1Field(
            Index = 6,
            Type = Asn1Type.SET_OF,
            Tagging = Asn1Tagging.IMPLICIT, 
            TagNumber = 1,
            Optional = true)]
        public List<Attribute> unsignedAttrs;
    }
}