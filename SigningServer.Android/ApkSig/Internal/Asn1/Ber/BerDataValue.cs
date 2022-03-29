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

namespace SigningServer.Android.ApkSig.Internal.Asn1.Ber
{
    /**
     * ASN.1 Basic Encoding Rules (BER) data value -- see {@code X.690}.
     */
    public class BerDataValue
    {
        private readonly ByteBuffer mEncoded;
        private readonly ByteBuffer mEncodedContents;
        private readonly int mTagClass;
        private readonly bool mConstructed;
        private readonly int mTagNumber;

        public BerDataValue(
            ByteBuffer encoded,
            ByteBuffer encodedContents,
            int tagClass,
            bool constructed,
            int tagNumber)
        {
            mEncoded = encoded;
            mEncodedContents = encodedContents;
            mTagClass = tagClass;
            mConstructed = constructed;
            mTagNumber = tagNumber;
        }

        /**
         * Returns the tag class of this data value. See {@link BerEncoding} {@code TAG_CLASS}
         * constants.
         */
        public int getTagClass()
        {
            return mTagClass;
        }

        /**
         * Returns {@code true} if the content octets of this data value are the complete BER encoding
         * of one or more data values, {@code false} if the content octets of this data value directly
         * represent the value.
         */
        public bool isConstructed()
        {
            return mConstructed;
        }

        /**
         * Returns the tag number of this data value. See {@link BerEncoding} {@code TAG_NUMBER}
         * constants.
         */
        public int getTagNumber()
        {
            return mTagNumber;
        }

        /**
         * Returns the encoded form of this data value.
         */
        public ByteBuffer getEncoded()
        {
            return mEncoded.slice();
        }

        /**
         * Returns the encoded contents of this data value.
         */
        public ByteBuffer getEncodedContents()
        {
            return mEncodedContents.slice();
        }

        /**
         * Returns a new reader of the contents of this data value.
         */
        public BerDataValueReader contentsReader()
        {
            return new ByteBufferBerDataValueReader(getEncodedContents());
        }

        /**
         * Returns a new reader which returns just this data value. This may be useful for re-reading
         * this value in different contexts.
         */
        public BerDataValueReader dataValueReader()
        {
            return new ParsedValueReader(this);
        }

        private sealed class ParsedValueReader : BerDataValueReader
        {
            private readonly BerDataValue mValue;
            private bool mValueOutput;

            public
                ParsedValueReader(BerDataValue value)
            {
                mValue = value;
            }

            public BerDataValue readDataValue()
            {
                if (mValueOutput)
                {
                    return null;
                }

                mValueOutput = true;
                return mValue;
            }
        }
    }
}