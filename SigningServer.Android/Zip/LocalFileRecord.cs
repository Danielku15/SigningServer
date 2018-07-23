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
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SigningServer.Android.Util;

namespace SigningServer.Android.Zip
{
    /// <summary>
    /// ZIP Local File record.
    /// The record consists of the Local File Header, file data, and (if present) Data Descriptor.
    /// </summary>
    public class LocalFileRecord
    {
        private const int RecordSignature = 0x04034b50;
        private const int HeaderSizeBytes = 30;

        private const int GpFlagsOffset = 6;
        private const int Crc32Offset = 14;
        private const int CompressedSizeOffset = 18;
        private const int UncompressedSizeOffset = 22;
        private const int NameLengthOffset = 26;
        private const int ExtraLengthOffset = 28;
        private const int NameOffset = HeaderSizeBytes;

        private const int DataDescriptorSizeBytesWithoutSignature = 12;
        private const int DataDescriptorSignature = 0x08074b50;


        public string Name { get; }
        public int NameSizeBytes { get; }
        public byte[] Extra { get; }
        public long StartOffsetInArchive { get; }

        /// <summary>
        /// Returns the size (in bytes) of this record.
        /// </summary>
        public long Size { get; }
        public int DataStartOffset { get; }
        public long DataSize { get; }
        /// <summary>
        /// Returns <code>true</code> if this record's file data is stored in compressed form.
        /// </summary>
        public bool IsDataCompressed { get; }
        public long UncompressedDataSize { get; }

        public int ExtraFieldStartOffsetInsideRecord => HeaderSizeBytes + NameSizeBytes;


        private LocalFileRecord(
            string name,
            int nameSizeBytes,
            byte[] extra,
            long startOffsetInArchive,
            long size,
            int dataStartOffset,
            long dataSize,
            bool isDataCompressed,
            long uncompressedDataSize)
        {
            Name = name;
            NameSizeBytes = nameSizeBytes;
            Extra = extra;
            StartOffsetInArchive = startOffsetInArchive;
            Size = size;
            DataStartOffset = dataStartOffset;
            DataSize = dataSize;
            IsDataCompressed = isDataCompressed;
            UncompressedDataSize = uncompressedDataSize;
        }

        /// <summary>
        /// Sends uncompressed data of this record into the the provided data sink.
        /// </summary>
        /// <param name="lfhSection"></param>
        /// <param name="sink"></param>
        public void OutputUncompressedData(DataSource lfhSection, Stream sink)
        {
            var dataStartOffsetInArchive = StartOffsetInArchive + DataStartOffset;
            try
            {
                if (IsDataCompressed)
                {
                    using (var adapter = new InflateSinkAdapter(sink, true))
                    {
                        lfhSection.Feed(dataStartOffsetInArchive, DataSize, adapter);
                        long actualUncompressedSize = adapter.OutputByteCount;
                        if (actualUncompressedSize != UncompressedDataSize)
                        {
                            throw new ZipFormatException(
                                "Unexpected size of uncompressed data of " + Name
                                                                           + ". Expected: " + UncompressedDataSize +
                                                                           " bytes"
                                                                           + ", actual: " + actualUncompressedSize +
                                                                           " bytes");
                        }
                    }
                }
                else
                {
                    lfhSection.Feed(dataStartOffsetInArchive, DataSize, sink);
                    // No need to check whether sink size is as expected because DataSource.feed is
                    // guaranteed to sink exactly the number of bytes requested.
                }
            }
            catch (IOException e)
            {
                throw new IOException(
                    "Failed to read data of " + ((IsDataCompressed) ? "compressed" : "uncompressed")
                                              + " entry " + Name,
                    e);
            }
            // Interestingly, Android doesn't check that uncompressed data's CRC-32 is as expected. We
            // thus don't check either.
        }

        /// <summary>
        /// Outputs this record and returns returns the number of bytes output.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="stream"></param>
        /// <returns></returns>
        public long OutputRecord(DataSource source, Stream stream)
        {
            var size = Size;
            source.Feed(StartOffsetInArchive, size, stream);
            return size;
        }

        /// <summary>
        /// Outputs this record, replacing its extra field with the provided one, and returns returns the
        /// number of bytes output.
        /// </summary>
        /// <param name="sourceApk"></param>
        /// <param name="extra"></param>
        /// <param name="output"></param>
        /// <returns></returns>
        public long OutputRecordWithModifiedExtra(DataSource sourceApk, byte[] extra, Stream output)
        {
            var recordStartOffsetInSource = StartOffsetInArchive;
            var extraStartOffsetInRecord = ExtraFieldStartOffsetInsideRecord;
            var extraSizeBytes = extra.Length;
            var headerSize = extraStartOffsetInRecord + extraSizeBytes;
            var header = new MemoryStream(headerSize);
            sourceApk.Feed(recordStartOffsetInSource, extraStartOffsetInRecord, header);
            header.Write(extra, 0, extra.Length);

            header.Position = ExtraLengthOffset;
            var bytes = BitConverter.GetBytes((ushort)extraSizeBytes);
            header.Write(bytes, 0, bytes.Length);

            var headerBytes = header.ToArray();
            long outputByteCount = headerBytes.Length;
            output.Write(headerBytes, 0, headerBytes.Length);

            var remainingRecordSize = Size - DataStartOffset;
            sourceApk.Feed(recordStartOffsetInSource + DataStartOffset, remainingRecordSize, output);
            outputByteCount += remainingRecordSize;
            return outputByteCount;
        }

        /// <summary>
        /// Returns the Local File record starting at the current position of the provided buffer
        /// and advances the buffer's position immediately past the end of the record. The record
        /// consists of the Local File Header, data, and (if present) Data Descriptor.
        /// </summary>
        /// <param name="apk"></param>
        /// <param name="cdRecord"></param>
        /// <param name="cdStartOffset"></param>
        /// <returns></returns>
        public static LocalFileRecord GetRecord(DataSource apk, CentralDirectoryRecord cdRecord, long cdStartOffset)
        {
            return GetRecord(
                apk,
                cdRecord,
                cdStartOffset,
                true, // obtain extra field contents
                true // include Data Descriptor (if present)
            );
        }

        /// <summary>
        /// Returns the Local File record starting at the current position of the provided buffer
        /// and advances the buffer's position immediately past the end of the record. The record
        /// consists of the Local File Header, data, and (if present) Data Descriptor.
        /// </summary>
        /// <param name="apk"></param>
        /// <param name="cdRecord"></param>
        /// <param name="cdStartOffset"></param>
        /// <param name="extraFieldContentsNeeded"></param>
        /// <param name="dataDescriptorIncluded"></param>
        /// <returns></returns>
        private static LocalFileRecord GetRecord(DataSource apk, CentralDirectoryRecord cdRecord, long cdStartOffset, bool extraFieldContentsNeeded, bool dataDescriptorIncluded)
        {
            // IMPLEMENTATION NOTE: This method attempts to mimic the behavior of Android platform
            // exhibited when reading an APK for the purposes of verifying its signatures.
            var entryName = cdRecord.Name;
            var cdRecordEntryNameSizeBytes = cdRecord.NameSizeBytes;
            var headerSizeWithName = HeaderSizeBytes + cdRecordEntryNameSizeBytes;
            var headerStartOffset = cdRecord.LocalFileHeaderOffset;
            var headerEndOffset = headerStartOffset + headerSizeWithName;
            if (headerEndOffset > cdStartOffset)
            {
                throw new ZipFormatException(
                        "Local File Header of " + entryName + " extends beyond start of Central"
                                + " Directory. LFH end: " + headerEndOffset
                                + ", CD start: " + cdStartOffset);
            }
            byte[] header;
            try
            {
                header = apk.GetByteBuffer(headerStartOffset, headerSizeWithName);
            }
            catch (IOException e)
            {
                throw new IOException("Failed to read Local File Header of " + entryName, e);
            }

            var recordSignature = BitConverter.ToInt32(header, 0);
            if (recordSignature != RecordSignature)
            {
                throw new ZipFormatException(
                        "Not a Local File Header record for entry " + entryName + ". Signature: 0x"
                                + (recordSignature & 0xffffffffL).ToString("X"));
            }
            var gpFlags = BitConverter.ToInt16(header, GpFlagsOffset);
            var dataDescriptorUsed = (gpFlags & ZipUtils.GpFlagDataDescriptorUsed) != 0;
            var cdDataDescriptorUsed =
                    (cdRecord.GpFlags & ZipUtils.GpFlagDataDescriptorUsed) != 0;
            if (dataDescriptorUsed != cdDataDescriptorUsed)
            {
                throw new ZipFormatException(
                        "Data Descriptor presence mismatch between Local File Header and Central"
                                + " Directory for entry " + entryName
                                + ". LFH: " + dataDescriptorUsed + ", CD: " + cdDataDescriptorUsed);
            }
            var uncompressedDataCrc32FromCdRecord = cdRecord.Crc32;
            var compressedDataSizeFromCdRecord = cdRecord.CompressedSize;
            var uncompressedDataSizeFromCdRecord = cdRecord.UncompressedSize;
            if (!dataDescriptorUsed)
            {
                long crc32 = BitConverter.ToUInt32(header, Crc32Offset);
                if (crc32 != uncompressedDataCrc32FromCdRecord)
                {
                    throw new ZipFormatException(
                            "CRC-32 mismatch between Local File Header and Central Directory for entry "
                                    + entryName + ". LFH: " + crc32
                                    + ", CD: " + uncompressedDataCrc32FromCdRecord);
                }
                long compressedSize = BitConverter.ToUInt32(header, CompressedSizeOffset);
                if (compressedSize != compressedDataSizeFromCdRecord)
                {
                    throw new ZipFormatException(
                            "Compressed size mismatch between Local File Header and Central Directory"
                                    + " for entry " + entryName + ". LFH: " + compressedSize
                                    + ", CD: " + compressedDataSizeFromCdRecord);
                }
                long uncompressedSize = BitConverter.ToUInt32(header, UncompressedSizeOffset);
                if (uncompressedSize != uncompressedDataSizeFromCdRecord)
                {
                    throw new ZipFormatException(
                            "Uncompressed size mismatch between Local File Header and Central Directory"
                                    + " for entry " + entryName + ". LFH: " + uncompressedSize
                                    + ", CD: " + uncompressedDataSizeFromCdRecord);
                }
            }
            int nameLength = BitConverter.ToUInt16(header, NameLengthOffset);
            if (nameLength > cdRecordEntryNameSizeBytes)
            {
                throw new ZipFormatException(
                        "Name mismatch between Local File Header and Central Directory for entry"
                                + entryName + ". LFH: " + nameLength
                                + " bytes, CD: " + cdRecordEntryNameSizeBytes + " bytes");
            }
            var name = CentralDirectoryRecord.GetName(header, NameOffset, nameLength);
            if (!entryName.Equals(name))
            {
                throw new ZipFormatException(
                        "Name mismatch between Local File Header and Central Directory. LFH: \""
                                + name + "\", CD: \"" + entryName + "\"");
            }
            int extraLength = BitConverter.ToUInt16(header, ExtraLengthOffset);
            var dataStartOffset = headerStartOffset + HeaderSizeBytes + nameLength + extraLength;
            long dataSize;
            var compressed =
                    (cdRecord.CompressionMethod != ZipUtils.CompressionMethodStored);
            if (compressed)
            {
                dataSize = compressedDataSizeFromCdRecord;
            }
            else
            {
                dataSize = uncompressedDataSizeFromCdRecord;
            }
            var dataEndOffset = dataStartOffset + dataSize;
            if (dataEndOffset > cdStartOffset)
            {
                throw new ZipFormatException(
                        "Local File Header data of " + entryName + " overlaps with Central Directory"
                                + ". LFH data start: " + dataStartOffset
                                + ", LFH data end: " + dataEndOffset + ", CD start: " + cdStartOffset);
            }
            var extra = new byte[0];
            if ((extraFieldContentsNeeded) && (extraLength > 0))
            {
                extra = apk.GetByteBuffer(
                        headerStartOffset + HeaderSizeBytes + nameLength, extraLength);
            }
            var recordEndOffset = dataEndOffset;
            // Include the Data Descriptor (if requested and present) into the record.
            if ((dataDescriptorIncluded) && ((gpFlags & ZipUtils.GpFlagDataDescriptorUsed) != 0))
            {
                // The record's data is supposed to be followed by the Data Descriptor. Unfortunately,
                // the descriptor's size is not known in advance because the spec lets the signature
                // field (the first four bytes) be omitted. Thus, there's no 100% reliable way to tell
                // how long the Data Descriptor record is. Most parsers (including Android) check
                // whether the first four bytes look like Data Descriptor record signature and, if so,
                // assume that it is indeed the record's signature. However, this is the wrong
                // conclusion if the record's CRC-32 (next field after the signature) has the same value
                // as the signature. In any case, we're doing what Android is doing.
                var dataDescriptorEndOffset =
                        dataEndOffset + DataDescriptorSizeBytesWithoutSignature;
                if (dataDescriptorEndOffset > cdStartOffset)
                {
                    throw new ZipFormatException(
                            "Data Descriptor of " + entryName + " overlaps with Central Directory"
                                    + ". Data Descriptor end: " + dataEndOffset
                                    + ", CD start: " + cdStartOffset);
                }
                var dataDescriptorPotentialSig = apk.GetByteBuffer(dataEndOffset, 4);
                if (BitConverter.ToInt32(dataDescriptorPotentialSig, 0) == DataDescriptorSignature)
                {
                    dataDescriptorEndOffset += 4;
                    if (dataDescriptorEndOffset > cdStartOffset)
                    {
                        throw new ZipFormatException(
                                "Data Descriptor of " + entryName + " overlaps with Central Directory"
                                        + ". Data Descriptor end: " + dataEndOffset
                                        + ", CD start: " + cdStartOffset);
                    }
                }
                recordEndOffset = dataDescriptorEndOffset;
            }
            var recordSize = recordEndOffset - headerStartOffset;
            var dataStartOffsetInRecord = HeaderSizeBytes + nameLength + extraLength;
            return new LocalFileRecord(
                    entryName,
                    cdRecordEntryNameSizeBytes,
                    extra,
                    headerStartOffset,
                    recordSize,
                    dataStartOffsetInRecord,
                    dataSize,
                    compressed,
                    uncompressedDataSizeFromCdRecord);
        }

        /// <summary>
        /// Outputs the specified Local File Header record with its data and returns the number of bytes output.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="lastModifiedTime"></param>
        /// <param name="lastModifiedDate"></param>
        /// <param name="compressedData"></param>
        /// <param name="crc32"></param>
        /// <param name="uncompressedSize"></param>
        /// <param name="output"></param>
        /// <returns></returns>
        public static long OutputRecordWithDeflateCompressedData(string name, int lastModifiedTime, int lastModifiedDate, byte[] compressedData, long crc32, long uncompressedSize, Stream output)
        {
            var nameBytes = Encoding.UTF8.GetBytes(name);
            var recordSize = HeaderSizeBytes + nameBytes.Length;
            var result = new BinaryWriter(new MemoryStream(recordSize));
            result.Write(RecordSignature);
            result.Write((ushort)0x14); // Minimum version needed to extract
            result.Write(ZipUtils.GpFlagEfs); // General purpose flag: UTF-8 encoded name
            result.Write((short)ZipUtils.CompressionMethodDeflated);
            result.Write((ushort)lastModifiedTime);
            result.Write((ushort)lastModifiedDate);
            result.Write((uint)crc32);
            result.Write((uint)compressedData.Length);
            result.Write((uint)uncompressedSize);
            result.Write((ushort)nameBytes.Length);
            result.Write((ushort)0); // Extra field length
            result.Write(nameBytes);

            var resultBytes = ((MemoryStream)result.BaseStream).ToArray();
            long outputByteCount = resultBytes.Length;
            output.Write(resultBytes, 0, resultBytes.Length);
            outputByteCount += compressedData.Length;
            output.Write(compressedData, 0, compressedData.Length);
            return outputByteCount;
        }

        /// <summary>
        /// Returns the uncompressed data pointed to by the provided ZIP Central Directory (CD) record.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="cdRecord"></param>
        /// <param name="cdStartOffsetInArchive"></param>
        /// <returns></returns>
        public static byte[] GetUncompressedData(DataSource source, CentralDirectoryRecord cdRecord, long cdStartOffsetInArchive)
        {
            byte[] result = new byte[cdRecord.UncompressedSize];
            var resultSink = new MemoryStream(result, true);
            OutputUncompressedData(
                source,
                cdRecord,
                cdStartOffsetInArchive,
                resultSink);
            return result;
        }

        /// <summary>
        /// Sends uncompressed data pointed to by the provided ZIP Central Directory (CD) record into the
        /// provided data sink.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="cdRecord"></param>
        /// <param name="cdStartOffsetInArchive"></param>
        /// <param name="sink"></param>
        public static void OutputUncompressedData(
            DataSource source,
            CentralDirectoryRecord cdRecord,
            long cdStartOffsetInArchive,
            Stream sink)
        {
            // IMPLEMENTATION NOTE: This method attempts to mimic the behavior of Android platform
            // exhibited when reading an APK for the purposes of verifying its signatures.
            // When verifying an APK, Android doesn't care reading the extra field or the Data
            // Descriptor.
            LocalFileRecord lfhRecord =
                GetRecord(
                    source,
                    cdRecord,
                    cdStartOffsetInArchive,
                    false, // don't care about the extra field
                    false // don't read the Data Descriptor
                );
            lfhRecord.OutputUncompressedData(source, sink);
        }

        private class InflateSinkAdapter : Stream
        {
            private readonly ByteCountingStream _byteCounter;
            private readonly MemoryStream _deflateInput;
            private readonly DeflateStream _deflateStream;

            private class ByteCountingStream : Stream
            {
                private readonly Stream _stream;

                public int OutputByteCount { get; private set; }

                public ByteCountingStream(Stream stream)
                {
                    _stream = stream;
                }

                public override void Flush()
                {
                    _stream.Flush();
                }

                public override long Seek(long offset, SeekOrigin origin)
                {
                    return _stream.Seek(offset, origin);
                }

                public override void SetLength(long value)
                {
                    _stream.SetLength(value);
                }

                public override int Read(byte[] buffer, int offset, int count)
                {
                    return _stream.Read(buffer, offset, count);
                }

                public override void Write(byte[] buffer, int offset, int count)
                {
                    _stream.Write(buffer, offset, count);
                    OutputByteCount += count;
                }

                public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
                {
                    return _stream.CopyToAsync(destination, bufferSize, cancellationToken);
                }

                public override void Close()
                {
                    _stream.Close();
                }

                protected override void Dispose(bool disposing)
                {
                    if (disposing)
                    {
                        _stream.Dispose();
                    }
                }

                public override Task FlushAsync(CancellationToken cancellationToken)
                {
                    return _stream.FlushAsync(cancellationToken);
                }

                public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
                {
                    return _stream.BeginRead(buffer, offset, count, callback, state);
                }

                public override int EndRead(IAsyncResult asyncResult)
                {
                    return _stream.EndRead(asyncResult);
                }

                public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
                {
                    return _stream.ReadAsync(buffer, offset, count, cancellationToken);
                }

                public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
                {
                    OutputByteCount += count;
                    return _stream.BeginWrite(buffer, offset, count, callback, state);
                }

                public override void EndWrite(IAsyncResult asyncResult)
                {
                    _stream.EndWrite(asyncResult);
                }

                public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
                {
                    OutputByteCount += count;
                    return _stream.WriteAsync(buffer, offset, count, cancellationToken);
                }

                public override int ReadByte()
                {
                    return _stream.ReadByte();
                }

                public override void WriteByte(byte value)
                {
                    _stream.WriteByte(value);
                    OutputByteCount++;
                }

                public override bool CanTimeout => _stream.CanTimeout;
                public override int ReadTimeout => _stream.ReadTimeout;
                public override int WriteTimeout => _stream.WriteTimeout;

                public override bool CanRead => _stream.CanRead;
                public override bool CanSeek => _stream.CanSeek;
                public override bool CanWrite => _stream.CanWrite;
                public override long Length => _stream.Length;
                public override long Position
                {
                    get => _stream.Position;
                    set => _stream.Position = value;
                }
            }

            public int OutputByteCount => _byteCounter.OutputByteCount;

            public InflateSinkAdapter(Stream stream, bool leaveOpen)
            {
                _byteCounter = new ByteCountingStream(stream);
                _deflateInput = new MemoryStream();
                _deflateStream = new DeflateStream(_deflateInput, CompressionMode.Decompress, leaveOpen);
            }


            public override void Flush()
            {
                _deflateStream.Flush();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new InvalidOperationException();
            }

            public override void SetLength(long value)
            {
                throw new InvalidOperationException();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new InvalidOperationException();
            }


            private byte[] _delegateBuffer = new byte[65535];
            public override void Write(byte[] buffer, int offset, int count)
            {
                var pos = _deflateInput.Position;
                _deflateInput.Write(buffer, 0, count);
                _deflateInput.Position = pos;

                int c;
                while ((c = _deflateStream.Read(_delegateBuffer, 0, _delegateBuffer.Length)) > 0)
                {
                    _byteCounter.Write(_delegateBuffer, 0, c);
                }
            }


            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => _deflateStream.Length;
            public override long Position
            {
                get => _deflateStream.Position;
                set => throw new InvalidOperationException();
            }
        }
    }
}