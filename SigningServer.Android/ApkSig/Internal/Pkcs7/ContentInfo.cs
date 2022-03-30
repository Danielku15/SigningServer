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

using System;
using SigningServer.Android.ApkSig.Internal.Asn1;

namespace SigningServer.Android.ApkSig.Internal.Pkcs7
{
    /**
     * PKCS #7 {@code ContentInfo} as specified in RFC 5652.
     */
    [Asn1Class(Type = Asn1Type.SEQUENCE)]
    public class ContentInfo
    {
        [Asn1Field(Index = 1, Type = Asn1Type.OBJECT_IDENTIFIER)]
        public String contentType;

        [Asn1Field(Index = 2, Type = Asn1Type.ANY, Tagging = Asn1Tagging.EXPLICIT, TagNumber = 0)]
        public Asn1OpaqueObject content;
    }
}