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

namespace SigningServer.Android.ApkSig.Internal.Asn1
{
    [AttributeUsage(AttributeTargets.Field)]
    public class Asn1FieldAttribute : Attribute
    {
        /** Index used to order fields in a container. Required for fields of SEQUENCE containers. */
        public int Index { get; set; } = 0;

        public Asn1TagClass Cls { get; set; } = Asn1TagClass.AUTOMATIC;

        public Asn1Type Type { get; set; } = Asn1Type.ANY;

        /** Tagging mode. Default: NORMAL. */
        public Asn1Tagging Tagging { get; set; } = Asn1Tagging.NORMAL;

        /** Tag number. Required when IMPLICIT and EXPLICIT tagging mode is used.*/
        public int TagNumber { get; set; } = -1;

        /** {@code true} if this field is optional. Ignored for fields of CHOICE containers. */
        public bool Optional { get; set; } = false;

        /** Type of elements. Used only for SET_OF or SEQUENCE_OF. */
        public Asn1Type ElementType { get; set; } = Asn1Type.ANY;
    }
}