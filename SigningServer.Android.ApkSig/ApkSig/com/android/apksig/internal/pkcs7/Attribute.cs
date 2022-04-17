// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

/*
 * Copyright (C) 2022 Daniel Kuschny (C# port)
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

namespace SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7
{
    /// <summary>
    /// PKCS #7 {@code Attribute} as specified in RFC 5652.
    /// </summary>
    [SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Class(Type = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Type.SEQUENCE)]
    public class Attribute
    {
        [SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Field(Index = 0, Type = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Type.OBJECT_IDENTIFIER)]
        public string attrType;
        
        [SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Field(Index = 1, Type = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Type.SET_OF)]
        public SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1OpaqueObject> attrValues;
        
    }
    
}
