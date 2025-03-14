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

namespace SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber
{
    /// <summary>
    /// {@link BerDataValueReader} which reads from a {@link ByteBuffer} containing BER-encoded data
    /// values. See {@code X.690} for the encoding.
    /// </summary>
    public class ByteBufferBerDataValueReader: SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueReader
    {
        internal readonly SigningServer.Android.IO.ByteBuffer mBuf;
        
        public ByteBufferBerDataValueReader(SigningServer.Android.IO.ByteBuffer buf)
        {
            if (buf == null)
            {
                throw new System.NullReferenceException("buf == null");
            }
            mBuf = buf;
        }
        
        public SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValue ReadDataValue()
        {
            int startPosition = mBuf.Position();
            if (!mBuf.HasRemaining())
            {
                return null;
            }
            byte firstIdentifierByte = mBuf.Get();
            int tagNumber = ReadTagNumber(firstIdentifierByte);
            bool constructed = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerEncoding.IsConstructed(firstIdentifierByte);
            if (!mBuf.HasRemaining())
            {
                throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Missing length");
            }
            int firstLengthByte = mBuf.Get() & 0xff;
            int contentsLength;
            int contentsOffsetInTag;
            if ((firstLengthByte & 0x80) == 0)
            {
                contentsLength = ReadShortFormLength(firstLengthByte);
                contentsOffsetInTag = mBuf.Position() - startPosition;
                SkipDefiniteLengthContents(contentsLength);
            }
            else if (firstLengthByte != 0x80)
            {
                contentsLength = ReadLongFormLength(firstLengthByte);
                contentsOffsetInTag = mBuf.Position() - startPosition;
                SkipDefiniteLengthContents(contentsLength);
            }
            else 
            {
                contentsOffsetInTag = mBuf.Position() - startPosition;
                contentsLength = constructed ? SkipConstructedIndefiniteLengthContents() : SkipPrimitiveIndefiniteLengthContents();
            }
            int endPosition = mBuf.Position();
            mBuf.Position(startPosition);
            int bufOriginalLimit = mBuf.Limit();
            mBuf.Limit(endPosition);
            SigningServer.Android.IO.ByteBuffer encoded = mBuf.Slice();
            mBuf.Position(mBuf.Limit());
            mBuf.Limit(bufOriginalLimit);
            encoded.Position(contentsOffsetInTag);
            encoded.Limit(contentsOffsetInTag + contentsLength);
            SigningServer.Android.IO.ByteBuffer encodedContents = encoded.Slice();
            encoded.Clear();
            return new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValue(encoded, encodedContents, SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerEncoding.GetTagClass(firstIdentifierByte), constructed, tagNumber);
        }
        
        internal int ReadTagNumber(byte firstIdentifierByte)
        {
            int tagNumber = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerEncoding.GetTagNumber(firstIdentifierByte);
            if (tagNumber == 0x1f)
            {
                return ReadHighTagNumber();
            }
            else 
            {
                return tagNumber;
            }
        }
        
        internal int ReadHighTagNumber()
        {
            int b;
            int result = 0;
            do
            {
                if (!mBuf.HasRemaining())
                {
                    throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Truncated tag number");
                }
                b = mBuf.Get();
                if (result > SigningServer.Android.TypeUtils.UnsignedRightShift(int.MaxValue, 7))
                {
                    throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Tag number too large");
                }
                result <<= 7;
                result |= b & 0x7f;
            }
            while ((b & 0x80) != 0);
            return result;
        }
        
        internal int ReadShortFormLength(int firstLengthByte)
        {
            return firstLengthByte & 0x7f;
        }
        
        internal int ReadLongFormLength(int firstLengthByte)
        {
            int byteCount = firstLengthByte & 0x7f;
            if (byteCount > 4)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Length too large: " + byteCount + " bytes");
            }
            int result = 0;
            for (int i = 0;i < byteCount;i++)
            {
                if (!mBuf.HasRemaining())
                {
                    throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Truncated length");
                }
                int b = mBuf.Get();
                if (result > SigningServer.Android.TypeUtils.UnsignedRightShift(int.MaxValue, 8))
                {
                    throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Length too large");
                }
                result <<= 8;
                result |= b & 0xff;
            }
            return result;
        }
        
        internal void SkipDefiniteLengthContents(int contentsLength)
        {
            if (mBuf.Remaining() < contentsLength)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Truncated contents. Need: " + contentsLength + " bytes, available: " + mBuf.Remaining());
            }
            mBuf.Position(mBuf.Position() + contentsLength);
        }
        
        internal int SkipPrimitiveIndefiniteLengthContents()
        {
            bool prevZeroByte = false;
            int bytesRead = 0;
            while (true)
            {
                if (!mBuf.HasRemaining())
                {
                    throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Truncated indefinite-length contents: " + bytesRead + " bytes read");
                }
                int b = mBuf.Get();
                bytesRead++;
                if (bytesRead < 0)
                {
                    throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Indefinite-length contents too long");
                }
                if (b == 0)
                {
                    if (prevZeroByte)
                    {
                        return bytesRead - 2;
                    }
                    prevZeroByte = true;
                }
                else 
                {
                    prevZeroByte = false;
                }
            }
        }
        
        internal int SkipConstructedIndefiniteLengthContents()
        {
            int startPos = mBuf.Position();
            while (mBuf.HasRemaining())
            {
                if ((mBuf.Remaining() > 1) && (mBuf.GetShort(mBuf.Position()) == 0))
                {
                    int contentsLength = mBuf.Position() - startPos;
                    mBuf.Position(mBuf.Position() + 2);
                    return contentsLength;
                }
                ReadDataValue();
            }
            throw new SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Ber.BerDataValueFormatException("Truncated indefinite-length contents: " + (mBuf.Position() - startPos) + " bytes read");
        }
        
    }
    
}
