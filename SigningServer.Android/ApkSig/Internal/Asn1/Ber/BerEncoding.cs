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
     * ASN.1 Basic Encoding Rules (BER) constants and helper methods. See {@code X.690}.
     */
    public static class BerEncoding
    {
        /**
         * Constructed vs primitive flag in the first identifier byte.
         */
        public const int ID_FLAG_CONSTRUCTED_ENCODING = 1 << 5;

        /**
         * Tag class: UNIVERSAL
         */
        public const int TAG_CLASS_UNIVERSAL = 0;

        /**
         * Tag class: APPLICATION
         */
        public const int TAG_CLASS_APPLICATION = 1;

        /**
         * Tag class: CONTEXT SPECIFIC
         */
        public const int TAG_CLASS_CONTEXT_SPECIFIC = 2;

        /**
         * Tag class: PRIVATE
         */
        public const int TAG_CLASS_PRIVATE = 3;

        /**
         * Tag number: BOOLEAN
         */
        public const int TAG_NUMBER_BOOLEAN = 0x1;

        /**
         * Tag number: INTEGER
         */
        public const int TAG_NUMBER_INTEGER = 0x2;

        /**
         * Tag number: BIT STRING
         */
        public const int TAG_NUMBER_BIT_STRING = 0x3;

        /**
         * Tag number: OCTET STRING
         */
        public const int TAG_NUMBER_OCTET_STRING = 0x4;

        /**
         * Tag number: NULL
         */
        public const int TAG_NUMBER_NULL = 0x05;

        /**
         * Tag number: OBJECT IDENTIFIER
         */
        public const int TAG_NUMBER_OBJECT_IDENTIFIER = 0x6;

        /**
         * Tag number: SEQUENCE
         */
        public const int TAG_NUMBER_SEQUENCE = 0x10;

        /**
         * Tag number: SET
         */
        public const int TAG_NUMBER_SET = 0x11;

        /**
         * Tag number: UTC_TIME
         */
        public const int TAG_NUMBER_UTC_TIME = 0x17;

        /**
         * Tag number: GENERALIZED_TIME
         */
        public const int TAG_NUMBER_GENERALIZED_TIME = 0x18;

        public static int getTagNumber(Asn1Type? dataType)
        {
            switch (dataType)
            {
                case Asn1Type.INTEGER:
                    return TAG_NUMBER_INTEGER;
                case Asn1Type.OBJECT_IDENTIFIER:
                    return TAG_NUMBER_OBJECT_IDENTIFIER;
                case Asn1Type.OCTET_STRING:
                    return TAG_NUMBER_OCTET_STRING;
                case Asn1Type.BIT_STRING:
                    return TAG_NUMBER_BIT_STRING;
                case Asn1Type.SET_OF:
                    return TAG_NUMBER_SET;
                case Asn1Type.SEQUENCE:
                case Asn1Type.SEQUENCE_OF:
                    return TAG_NUMBER_SEQUENCE;
                case Asn1Type.UTC_TIME:
                    return TAG_NUMBER_UTC_TIME;
                case Asn1Type.GENERALIZED_TIME:
                    return TAG_NUMBER_GENERALIZED_TIME;
                case Asn1Type.BOOLEAN:
                    return TAG_NUMBER_BOOLEAN;
                default:
                    throw new ArgumentException("Unsupported data type: " + dataType);
            }
        }

        public static int getTagClass(Asn1TagClass tagClass)
        {
            switch (tagClass)
            {
                case Asn1TagClass.APPLICATION:
                    return TAG_CLASS_APPLICATION;
                case Asn1TagClass.CONTEXT_SPECIFIC:
                    return TAG_CLASS_CONTEXT_SPECIFIC;
                case Asn1TagClass.PRIVATE:
                    return TAG_CLASS_PRIVATE;
                case Asn1TagClass.UNIVERSAL:
                    return TAG_CLASS_UNIVERSAL;
                default:
                    throw new ArgumentException("Unsupported tag class: " + tagClass);
            }
        }

        public static string tagClassToString(int typeClass)
        {
            switch (typeClass)
            {
                case TAG_CLASS_APPLICATION:
                    return "APPLICATION";
                case TAG_CLASS_CONTEXT_SPECIFIC:
                    return "";
                case TAG_CLASS_PRIVATE:
                    return "PRIVATE";
                case TAG_CLASS_UNIVERSAL:
                    return "UNIVERSAL";
                default:
                    throw new ArgumentException("Unsupported type class: " + typeClass);
            }
        }

        public static string tagClassAndNumberToString(int tagClass, int tagNumber)
        {
            string classString = tagClassToString(tagClass);
            string numberString = tagNumberToString(tagNumber);
            return string.IsNullOrEmpty(classString) ? numberString : classString + " " + numberString;
        }


        public static string tagNumberToString(int tagNumber)
        {
            switch (tagNumber)
            {
                case TAG_NUMBER_INTEGER:
                    return "INTEGER";
                case TAG_NUMBER_OCTET_STRING:
                    return "OCTET STRING";
                case TAG_NUMBER_BIT_STRING:
                    return "BIT STRING";
                case TAG_NUMBER_NULL:
                    return "NULL";
                case TAG_NUMBER_OBJECT_IDENTIFIER:
                    return "OBJECT IDENTIFIER";
                case TAG_NUMBER_SEQUENCE:
                    return "SEQUENCE";
                case TAG_NUMBER_SET:
                    return "SET";
                case TAG_NUMBER_BOOLEAN:
                    return "BOOLEAN";
                case TAG_NUMBER_GENERALIZED_TIME:
                    return "GENERALIZED TIME";
                case TAG_NUMBER_UTC_TIME:
                    return "UTC TIME";
                default:
                    return "0x" + tagNumber.ToString("X");
            }
        }

        /**
         * Returns {@code true} if the provided first identifier byte indicates that the data value uses
         * constructed encoding for its contents, or {@code false} if the data value uses primitive
         * encoding for its contents.
         */
        public static bool isConstructed(byte firstIdentifierByte)
        {
            return (firstIdentifierByte & ID_FLAG_CONSTRUCTED_ENCODING) != 0;
        }

        /**
         * Returns the tag class encoded in the provided first identifier byte. See {@code TAG_CLASS}
         * constants.
         */
        public static int getTagClass(byte firstIdentifierByte)
        {
            return (firstIdentifierByte & 0xff) >> 6;
        }

        public static byte setTagClass(byte firstIdentifierByte, int tagClass)
        {
            return (byte)((firstIdentifierByte & 0x3f) | (tagClass << 6));
        }

        /**
         * Returns the tag number encoded in the provided first identifier byte. See {@code TAG_NUMBER}
         * constants.
         */
        public static int getTagNumber(byte firstIdentifierByte)
        {
            return firstIdentifierByte & 0x1f;
        }

        public static byte setTagNumber(byte firstIdentifierByte, int tagNumber)
        {
            return (byte)((firstIdentifierByte & ~0x1f) | tagNumber);
        }
    }
}