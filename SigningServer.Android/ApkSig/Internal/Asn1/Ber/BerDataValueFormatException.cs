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

namespace SigningServer.Android.ApkSig.Internal.Asn1.Ber
{
    /**
     * Indicates that an ASN.1 data value being read could not be decoded using
     * Basic Encoding Rules (BER).
     */
    public class BerDataValueFormatException : Exception
    {
        public BerDataValueFormatException(string message) : base(message)
        {
        }

        public BerDataValueFormatException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}