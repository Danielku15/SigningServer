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
using SigningServer.Android.ApkSig.Internal.Asn1;

namespace SigningServer.Android.ApkSig.Internal.X509
{
    /**
     * X501 {@code Name} as specified in RFC 5280.
     */
    [Asn1Class(Type = Asn1Type.CHOICE)]
    public class Name
    {
        // This field is the RDNSequence specified in RFC 5280.
        [Asn1Field(Index = 0, Type = Asn1Type.SEQUENCE_OF)]
        public List<RelativeDistinguishedName> relativeDistinguishedNames;
    }
}