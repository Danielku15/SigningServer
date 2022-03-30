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

using System;
using SigningServer.Android.ApkSig.Internal.Asn1;

namespace SigningServer.Android.ApkSig.Internal.X509
{
    /**
     * {@code AttributeTypeAndValue} as specified in RFC 5280.
     */
    [Asn1Class(Type = Asn1Type.SEQUENCE)]
    public class AttributeTypeAndValue {

        [Asn1Field(Index = 0, Type = Asn1Type.OBJECT_IDENTIFIER)]
        public String attrType;

        [Asn1Field(Index = 1, Type = Asn1Type.ANY)]
        public Asn1OpaqueObject attrValue;
    }
}