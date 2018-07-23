/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2018 Daniel Kuschny (C# port based on oreo-master)
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
using System.Collections.Generic;
using System.IO;
using System.Text;
using SigningServer.Android.Util;

namespace SigningServer.Android.Apk
{
    /// <summary>
    /// XML pull style parser of Android binary XML resources, such as <code>AndroidManifest.xml</code>.
    /// </summary>
    /// <remarks>
    /// For an input document, the parser outputs an event stream (see {@code EVENT_... constants} via
    /// <see cref="EventType"/> and <see cref="Next"/> methods. Additional information about the current
    /// event can be obtained via an assortment of getters, for example, <see cref="Name"/> or
    /// <see cref="getAttributeNameResourceId"/>.
    /// </remarks>
    class AndroidBinXmlParser
    {
        public const int EndOfDocument = 2;
        public const int EventStartElement = 3;
        public const int EventEndElement = 4;

        private const long NoNamespace = 0xffffffffL;

        public const int ValueTypeUnsupported = 0;
        public const int ValueTypeString = 1;
        public const int ValueTypeInt = 2;
        public const int ValueTypeReference = 3;
        public const int ValueTypeBoolean = 4;



        private readonly BinaryReader _xml;
        private StringPool _stringPool;
        private List<Attribute> _currentElementAttributes;
        private int _currentElementAttrSizeBytes;
        private byte[] _currentElementAttributesContents;
        private ResourceMap _resourceMap;

        public int EventType { get; private set; }
        public int Depth { get; private set; }

        public string Name { get; private set; }
        public string Namespace { get; private set; }

        public int AttributeCount { get; private set; }


        public AndroidBinXmlParser(byte[] xml)
        {
            using (var reader = new BinaryReader(new MemoryStream(xml)))
            {
                Chunk resXmlChunk = null;
                while (reader.BaseStream.CanRead)
                {
                    Chunk chunk = Chunk.Get(reader);
                    if (chunk == null)
                    {
                        break;
                    }
                    if (chunk.Type == Chunk.TypeResXml)
                    {
                        resXmlChunk = chunk;
                        break;
                    }
                }
                if (resXmlChunk == null)
                {
                    throw new FormatException("No XML chunk in file");
                }
                _xml = new BinaryReader(new MemoryStream(resXmlChunk.Contents));
            }
        }

        /// <summary>
        /// Returns the resource ID corresponding to the name of the specified attribute of the current
        /// element or <code>0</code> if the name is not associated with a resource ID.
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public int GetAttributeNameResourceId(int index)
        {
            return GetAttribute(index).NameResourceId;
        }

        /// <summary>
        /// Returns the value type of the specified attribute of the current element. See
        /// <code>VALUE_TYPE_...</code> constants.
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public int GetAttributeValueType(int index)
        {
            int type = GetAttribute(index).ValueType;
            switch (type)
            {
                case Attribute.TypeString:
                    return ValueTypeString;
                case Attribute.TypeIntDec:
                case Attribute.TypeIntHex:
                case Attribute.TypeReference:
                    return ValueTypeInt;
                case Attribute.TypeIntBoolean:
                    return ValueTypeBoolean;
                default:
                    return ValueTypeUnsupported;
            }
        }

        /// <summary>
        /// Returns the string value of the specified attribute of the current element. See
        /// <code>VALUE_TYPE_...</code> constants.
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public string GetAttributeStringValue(int index)
        {
            return GetAttribute(index).StringValue;
        }


        /// <summary>
        /// Returns the integer value of the specified attribute of the current element. See
        /// <code>VALUE_TYPE_...</code>  constants.
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public int GetAttributeIntValue(int index)
        {
            return GetAttribute(index).IntValue;
        }

        private Attribute GetAttribute(int index)
        {
            if (EventType != EventStartElement)
            {
                throw new IndexOutOfRangeException("Current event not a START_ELEMENT");
            }
            if (index < 0)
            {
                throw new IndexOutOfRangeException("index must be >= 0");
            }
            if (index >= AttributeCount)
            {
                throw new IndexOutOfRangeException(
                    "index must be <= attr count (" + AttributeCount + ")");
            }
            ParseCurrentElementAttributesIfNotParsed();
            return _currentElementAttributes[index];
        }

        private void ParseCurrentElementAttributesIfNotParsed()
        {
            if (_currentElementAttributes != null)
            {
                return;
            }

            _currentElementAttributes = new List<Attribute>(AttributeCount);

            for (int i = 0; i < AttributeCount; i++)
            {
                int startPosition = i * _currentElementAttrSizeBytes;
                var attr =
                    SliceFromTo(
                        new MemoryStream(_currentElementAttributesContents),
                        startPosition,
                        startPosition + _currentElementAttrSizeBytes);

                var attrReader = new BinaryReader(new MemoryStream(attr));

                // ReSharper disable once UnusedVariable
                long nsId = attrReader.ReadUInt32();
                long nameId = attrReader.ReadUInt32();
                attrReader.BaseStream.Position += 7; // skip ignored fields
                int valueType = attrReader.ReadByte();
                long valueData = attrReader.ReadUInt32();
                _currentElementAttributes.Add(
                    new Attribute(
                        nameId,
                        valueType,
                        (int)valueData,
                        _stringPool,
                        _resourceMap));
            }

        }

        /// <summary>
        /// Advances to the next parsing event and returns its type. See <code>EVENT_...</code> constants.
        /// </summary>
        /// <returns></returns>
        public int Next()
        {
            // Decrement depth if the previous event was "end element".
            if (EventType == EventEndElement)
            {
                Depth--;
            }
            // Read events from document, ignoring events that we don't report to caller. Stop at the
            // earliest event which we report to caller.
            while (_xml.BaseStream.Remaining() > 0)
            {
                Chunk chunk = Chunk.Get(_xml);
                if (chunk == null)
                {
                    break;
                }
                switch (chunk.Type)
                {
                    case Chunk.TypeStringPool:
                        if (_stringPool != null)
                        {
                            throw new FormatException("Multiple string pools not supported");
                        }
                        _stringPool = new StringPool(chunk);
                        break;
                    case Chunk.ResXmlTypeStartElement:
                        {
                            if (_stringPool == null)
                            {
                                throw new FormatException(
                                        "Named element encountered before string pool");
                            }
                            var contents = chunk.Contents;
                            if (contents.Length < 20)
                            {
                                throw new FormatException(
                                        "Start element chunk too short. Need at least 20 bytes. Available: "
                                                + contents.Length + " bytes");
                            }
                            var contentReader = new BinaryReader(new MemoryStream(contents));
                            long nsId = contentReader.ReadUInt32();
                            long nameId = contentReader.ReadUInt32();
                            int attrStartOffset = contentReader.ReadUInt16();
                            int attrSizeBytes = contentReader.ReadUInt16();
                            int attrCount = contentReader.ReadUInt16();
                            long attrEndOffset = attrStartOffset + ((long)attrCount) * attrSizeBytes;
                            contentReader.BaseStream.Position = 0;
                            if (attrStartOffset > contents.Length)
                            {
                                throw new FormatException(
                                        "Attributes start offset out of bounds: " + attrStartOffset
                                            + ", max: " + contents.Length);
                            }
                            if (attrEndOffset > contents.Length)
                            {
                                throw new FormatException(
                                        "Attributes end offset out of bounds: " + attrEndOffset
                                            + ", max: " + contents.Length);
                            }
                            Name = _stringPool.GetString(nameId);
                            Namespace =
                                    (nsId == NoNamespace) ? "" : _stringPool.GetString(nsId);
                            AttributeCount = attrCount;
                            _currentElementAttributes = null;
                            _currentElementAttrSizeBytes = attrSizeBytes;
                            _currentElementAttributesContents =
                                    SliceFromTo(contentReader.BaseStream, attrStartOffset, attrEndOffset);
                            Depth++;
                            return EventType = EventStartElement;
                        }
                    case Chunk.ResXmlTypeEndElement:
                        {
                            if (_stringPool == null)
                            {
                                throw new FormatException(
                                        "Named element encountered before string pool");
                            }
                            var contents = chunk.Contents;
                            if (contents.Length < 8)
                            {
                                throw new FormatException(
                                        "End element chunk too short. Need at least 8 bytes. Available: "
                                                + contents.Length + " bytes");
                            }
                            var contentReader = new BinaryReader(new MemoryStream(contents));

                            long nsId = contentReader.ReadUInt32();
                            long nameId = contentReader.ReadUInt32();
                            Name = _stringPool.GetString(nameId);
                            Namespace =
                                    (nsId == NoNamespace) ? "" : _stringPool.GetString(nsId);
                            EventType = EventEndElement;
                            _currentElementAttributes = null;
                            _currentElementAttributesContents = null;
                            return EventType;
                        }
                    case Chunk.ResXmlTypeResourceMap:
                        if (_resourceMap != null)
                        {
                            throw new FormatException("Multiple resource maps not supported");
                        }
                        _resourceMap = new ResourceMap(chunk);
                        break;
                }
            }
            return EventType = EndOfDocument;
        }


        /// <summary>
        /// Returns new byte buffer whose content is a shared subsequence of this buffer's content
        /// between the specified start (inclusive) and end (exclusive) positions. As opposed to
        /// <see cref="ByteBuffer.Slice"/>, the returned buffer's byte order is the same as the source
        /// buffer's byte order.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="start"></param>
        /// <param name="end"></param>
        /// <returns></returns>
        private static byte[] SliceFromTo(Stream source, long start, long end)
        {
            var originalPosition = source.Position;
            try
            {
                source.Position = start;
                var length = end - start;
                byte[] data = new byte[length];
                source.Read(data, 0, (int)length);
                return data;
            }
            finally
            {
                source.Position = originalPosition;
            }
        }

        /// <summary>
        /// Chunk of a document. Each chunk is tagged with a type and consists of a header followed by contents.
        /// </summary>
        private class Chunk
        {
            public const int ResXmlTypeStartElement = 0x0102;
            public const int ResXmlTypeEndElement = 0x0103;
            public const int ResXmlTypeResourceMap = 0x0180;

            public const int HeaderMinSizeBytes = 8;

            public const int TypeStringPool = 1;
            public const int TypeResXml = 3;

            public int Type { get; }
            public byte[] Header { get; }
            public byte[] Contents { get; }

            public Chunk(int type, byte[] header, byte[] contents)
            {
                Type = type;
                Header = header;
                Contents = contents;
            }

            public static Chunk Get(BinaryReader input)
            {
                if ((input.BaseStream.Remaining()) < HeaderMinSizeBytes)
                {
                    // Android ignores the last chunk if its header is too big to fit into the file
                    input.BaseStream.Position = input.BaseStream.Length;
                    return null;
                }
                long originalPosition = input.BaseStream.Position;
                int type = input.ReadUInt16();
                int headerSize = input.ReadUInt16();
                long chunkSize = input.ReadUInt32();
                long chunkRemaining = chunkSize - 8;
                if (chunkRemaining > input.BaseStream.Remaining())
                {
                    // Android ignores the last chunk if it's too big to fit into the file
                    input.BaseStream.Position = input.BaseStream.Length;
                    return null;
                }
                if (headerSize < HeaderMinSizeBytes)
                {
                    throw new FormatException(
                        "Malformed chunk: header too short: " + headerSize + " bytes");
                }
                else if (headerSize > chunkSize)
                {
                    throw new FormatException(
                        "Malformed chunk: header too long: " + headerSize + " bytes. Chunk size: "
                        + chunkSize + " bytes");
                }
                long contentStartPosition = originalPosition + headerSize;
                long chunkEndPosition = originalPosition + chunkSize;
                Chunk chunk =
                    new Chunk(
                        type,
                        AndroidBinXmlParser.SliceFromTo(input.BaseStream, originalPosition, contentStartPosition),
                        AndroidBinXmlParser.SliceFromTo(input.BaseStream, contentStartPosition, chunkEndPosition));
                input.BaseStream.Position = chunkEndPosition;
                return chunk;
            }
        }

        private class Attribute
        {
            public const int TypeReference = 1;
            public const int TypeString = 3;
            public const int TypeIntDec = 0x10;
            public const int TypeIntHex = 0x11;
            public const int TypeIntBoolean = 0x12;

            private readonly StringPool _stringPool;
            private readonly ResourceMap _resourceMap;

            public long NameId { get; set; }
            public int ValueType { get; set; }
            public int ValueData { get; set; }

            public int NameResourceId => _resourceMap != null ? _resourceMap.GetResourceId(NameId) : 0;

            public int IntValue
            {
                get
                {
                    switch (ValueType)
                    {
                        case TypeReference:
                        case TypeIntDec:
                        case TypeIntHex:
                        case TypeIntBoolean:
                            return ValueData;
                        default:
                            throw new FormatException("Cannot coerce to int: value type " + ValueType);
                    }
                }
            }

            public string StringValue
            {
                get
                {
                    switch (ValueType)
                    {
                        case TypeString:
                            return _stringPool.GetString(ValueData & 0xffffffffL);
                        case TypeIntDec:
                            return ValueData.ToString();
                        case TypeIntHex:
                            return "0x" + ValueData.ToString("X");
                        case TypeIntBoolean:
                            return (ValueData != 0).ToString();
                        case TypeReference:
                            return "@" + ValueData.ToString("X");
                        default:
                            throw new FormatException(
                                "Cannot coerce to string: value type " + ValueType);
                    }
                }
            }

            public Attribute(
                long nameId,
                int valueType,
                int valueData,
                StringPool stringPool,
                ResourceMap resourceMap)
            {
                NameId = nameId;
                ValueType = valueType;
                ValueData = valueData;
                _stringPool = stringPool;
                _resourceMap = resourceMap;
            }
        }

        /// <summary>
        /// Resource map of a document. Resource IDs are referenced by their <code>0</code>-based index in the
        /// map.
        /// </summary>
        private class ResourceMap
        {
            private readonly byte[] _chunkContents;
            private readonly int _entryCount;

            /// <summary>
            /// Constructs a new resource map from the provided chunk.
            /// </summary>
            /// <param name="chunk"></param>
            public ResourceMap(Chunk chunk)
            {
                _chunkContents = chunk.Contents;
                // Each entry of the map is four bytes long, containing the int32 resource ID.
                _entryCount = _chunkContents.Length / 4;
            }

            /// <summary>
            /// Returns the resource ID located at the specified <code>0</code>-based index in this pool or
            /// <code>0</code> if the index is out of range.
            /// </summary>
            /// <param name="index"></param>
            /// <returns></returns>
            public int GetResourceId(long index)
            {
                if ((index < 0) || (index >= _entryCount))
                {
                    return 0;
                }
                int idx = (int)index;
                // Each entry of the map is four bytes long, containing the int32 resource ID.
                return BitConverter.ToInt32(_chunkContents, idx * 4);
            }
        }

        /// <summary>
        /// String pool of a document. Strings are referenced by their {@code 0}-based index in the pool.
        /// </summary>
        private class StringPool
        {
            private const int FlagUtf8 = 1 << 8;

            private readonly int _stringCount;
            private readonly byte[] _stringsSection;
            private readonly bool _utf8Encoded;
            private readonly byte[] _chunkContents;

            private readonly Dictionary<int, string> _cachedStrings = new Dictionary<int, string>();

            /// <summary>
            /// Constructs a new string pool from the provided chunk.
            /// </summary>
            /// <param name="chunk"></param>
            public StringPool(Chunk chunk)
            {
                var header = chunk.Header;
                int headerSizeBytes = header.Length;
                var headerReader = new BinaryReader(new MemoryStream(header));

                headerReader.BaseStream.Position = Chunk.HeaderMinSizeBytes;
                if (headerReader.BaseStream.Remaining() < 20)
                {
                    throw new FormatException(
                            "XML chunk's header too short. Required at least 20 bytes. Available: "
                                    + headerReader.BaseStream.Remaining() + " bytes");
                }
                long stringCount = headerReader.ReadUInt32();
                if (stringCount > int.MaxValue)
                {
                    throw new FormatException("Too many strings: " + stringCount);
                }
                _stringCount = (int)stringCount;
                long styleCount = headerReader.ReadUInt32();
                if (styleCount > int.MaxValue)
                {
                    throw new FormatException("Too many styles: " + styleCount);
                }
                long flags = headerReader.ReadUInt32();
                long stringsStartOffset = headerReader.ReadUInt32();
                long stylesStartOffset = headerReader.ReadUInt32();
                var contents = chunk.Contents;
                var contentReader = new BinaryReader(new MemoryStream(contents));
                if (_stringCount > 0)
                {
                    int stringsSectionStartOffsetInContents =
                            (int)(stringsStartOffset - headerSizeBytes);
                    int stringsSectionEndOffsetInContents;
                    if (styleCount > 0)
                    {
                        // Styles section follows the strings section
                        if (stylesStartOffset < stringsStartOffset)
                        {
                            throw new FormatException(
                                    "Styles offset (" + stylesStartOffset + ") < strings offset ("
                                            + stringsStartOffset + ")");
                        }
                        stringsSectionEndOffsetInContents = (int)(stylesStartOffset - headerSizeBytes);
                    }
                    else
                    {
                        stringsSectionEndOffsetInContents = (int)contentReader.BaseStream.Remaining();
                    }
                    _stringsSection =
                            SliceFromTo(
                                    contentReader.BaseStream,
                                    stringsSectionStartOffsetInContents,
                                    stringsSectionEndOffsetInContents);
                }
                else
                {
                    _stringsSection = new byte[0];
                }
                _utf8Encoded = (flags & FlagUtf8) != 0;
                _chunkContents = contents;
            }

            public string GetString(long index)
            {
                if (index < 0)
                {
                    throw new FormatException("Unsuported string index: " + index);
                }
                else if (index >= _stringCount)
                {
                    throw new FormatException(
                        "Unsuported string index: " + index + ", max: " + (_stringCount - 1));
                }
                int idx = (int)index;
                if (_cachedStrings.TryGetValue(idx, out var result))
                {
                    return result;
                }
                long offsetInStringsSection = BitConverter.ToUInt32(_chunkContents, idx * 4);
                if (offsetInStringsSection >= _stringsSection.Length)
                {
                    throw new FormatException(
                        "Offset of string idx " + idx + " out of bounds: " + offsetInStringsSection
                        + ", max: " + (_stringsSection.Length - 1));
                }
                result =
                    (_utf8Encoded)
                        ? GetLengthPrefixedUtf8EncodedString(_stringsSection, (int)offsetInStringsSection)
                        : GetLengthPrefixedUtf16EncodedString(_stringsSection, (int)offsetInStringsSection);
                _cachedStrings[idx] = result;
                return result;
            }

            private static String GetLengthPrefixedUtf16EncodedString(byte[] encoded, int offset)
            {
                // If the length (in uint16s) is 0x7fff or lower, it is stored as a single uint16.
                // Otherwise, it is stored as a big-endian uint32 with highest bit set. Thus, the range
                // of supported values is 0 to 0x7fffffff inclusive.
                int lengthChars = BitConverter.ToUInt16(encoded, offset);
                offset += 2;
                if ((lengthChars & 0x8000) != 0)
                {
                    lengthChars = ((lengthChars & 0x7fff) << 16) | BitConverter.ToUInt16(encoded, offset + 2);
                    offset += 2;
                }
                if (lengthChars > int.MaxValue / 2)
                {
                    throw new FormatException("String too long: " + lengthChars + " uint16s");
                }
                int lengthBytes = lengthChars * 2;

                // Reproduce the behavior of Android runtime which requires that the UTF-16 encoded
                // array of bytes is NULL terminated.
                if ((encoded[offset + lengthBytes] != 0) || (encoded[offset + lengthBytes + 1] != 0))
                {
                    throw new FormatException("UTF-16 encoded form of string not NULL terminated");
                }
                return Encoding.Unicode.GetString(encoded, offset, lengthBytes);
            }

            private static String GetLengthPrefixedUtf8EncodedString(byte[] encoded, int offset)
            {
                // If the length (in bytes) is 0x7f or lower, it is stored as a single uint8. Otherwise,
                // it is stored as a big-endian uint16 with highest bit set. Thus, the range of
                // supported values is 0 to 0x7fff inclusive.
                // Skip UTF-16 encoded length (in uint16s)
                int lengthBytes = encoded[offset];
                offset++;
                if ((lengthBytes & 0x80) != 0)
                {
                    lengthBytes = ((lengthBytes & 0x7f) << 8) | encoded[offset];
                    offset++;
                }
                // Read UTF-8 encoded length (in bytes)
                lengthBytes = encoded[offset];
                offset++;
                if ((lengthBytes & 0x80) != 0)
                {
                    lengthBytes = ((lengthBytes & 0x7f) << 8) | encoded[offset];
                    offset++;
                }

                // Reproduce the behavior of Android runtime which requires that the UTF-8 encoded array
                // of bytes is NULL terminated.
                if (encoded[offset + lengthBytes] != 0)
                {
                    throw new FormatException("UTF-8 encoded form of string not NULL terminated");
                }
                return Encoding.UTF8.GetString(encoded, offset, lengthBytes);
            }

        }
    }
}
