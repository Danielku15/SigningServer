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
using System.Text;
using SigningServer.Android.Util;

namespace SigningServer.Android.Zip
{
    /// <summary>
    /// ZIP Central Directory (CD) Record.
    /// </summary>
    public class CentralDirectoryRecord
    {
        private const int RecordSignature = 0x02014b50;
        private const int HeaderSizeBytes = 46;

        private const int GpFlagsOffset = 8;
        private const int LocalFileHeaderOffsetOffset = 42;
        private const int NameOffset = HeaderSizeBytes;

        public byte[] Data { get; }
        public short GpFlags { get; }
        public short CompressionMethod { get; }
        public int LastModificationTime { get; }
        public int LastModificationDate { get; }
        public long Crc32 { get; }
        public long CompressedSize { get; }
        public long UncompressedSize { get; }
        public long LocalFileHeaderOffset { get; }
        public string Name { get; }
        public int NameSizeBytes { get; }
        public long Size => Data.Length;

        private CentralDirectoryRecord(
            byte[] data,
            short gpFlags,
            short compressionMethod,
            int lastModificationTime,
            int lastModificationDate,
            long crc32,
            long compressedSize,
            long uncompressedSize,
            long localFileHeaderOffset,
            string name,
            int nameSizeBytes)
        {
            Data = data;
            GpFlags = gpFlags;
            CompressionMethod = compressionMethod;
            LastModificationDate = lastModificationDate;
            LastModificationTime = lastModificationTime;
            Crc32 = crc32;
            CompressedSize = compressedSize;
            UncompressedSize = uncompressedSize;
            LocalFileHeaderOffset = localFileHeaderOffset;
            Name = name;
            NameSizeBytes = nameSizeBytes;
        }

        /// <summary>
        /// Returns the Central Directory Record starting at the current position of the provided buffer
        /// and advances the buffer's position immediately past the end of the record.
        /// </summary>
        /// <param name="buf"></param>
        /// <returns></returns>
        public static CentralDirectoryRecord GetRecord(DataSource buf)
        {
            if (buf.Remaining < HeaderSizeBytes)
            {
                throw new ZipFormatException(
                    "Input too short. Need at least: " + HeaderSizeBytes
                                                       + " bytes, available: " + buf.Remaining + " bytes");
            }

            var originalPosition = buf.Position;
            var recordSignature = buf.ReadInt32();
            if (recordSignature != RecordSignature)
            {
                throw new ZipFormatException(
                    "Not a Central Directory record. Signature: 0x"
                    + (recordSignature & 0xffffffffL).ToString("X"));
            }
            buf.Position = (originalPosition + GpFlagsOffset);
            var gpFlags = buf.ReadInt16();
            var compressionMethod = buf.ReadInt16();
            var lastModificationTime = buf.ReadUInt16();
            var lastModificationDate = buf.ReadUInt16();
            var crc32 = buf.ReadUInt32();
            var compressedSize = buf.ReadUInt32();
            var uncompressedSize = buf.ReadUInt32();
            var nameSize = buf.ReadUInt16();
            var extraSize = buf.ReadUInt16();
            var commentSize = buf.ReadUInt16();
            buf.Position = (originalPosition + LocalFileHeaderOffsetOffset);
            var localFileHeaderOffset = buf.ReadUInt32();
            buf.Position = (originalPosition);
            var recordSize = HeaderSizeBytes + nameSize + extraSize + commentSize;

            if (recordSize > buf.Remaining)
            {
                throw new ZipFormatException(
                    "Input too short. Need: " + recordSize + " bytes, available: "
                    +  buf.Remaining + " bytes");
            }
            var name = GetName(buf, originalPosition + NameOffset, nameSize);
            var recordBuf = buf.GetByteBuffer(originalPosition, recordSize);
            var recordEndInBuf = originalPosition + recordSize;

            // Consume this record
            buf.Position = recordEndInBuf;
            return new CentralDirectoryRecord(
                recordBuf,
                gpFlags,
                compressionMethod,
                lastModificationTime,
                lastModificationDate,
                crc32,
                compressedSize,
                uncompressedSize,
                localFileHeaderOffset,
                name,
                nameSize);
        }

        internal static string GetName(DataSource record, long position, long nameLengthBytes)
        {
            var pos = record.Position;
            var nameBytes = record.GetByteBuffer(position, nameLengthBytes);
            record.Position = pos;
            return Encoding.UTF8.GetString(nameBytes);
        }

        internal static string GetName(byte[] nameBytes, long position, long nameLengthBytes)
        {
            return Encoding.UTF8.GetString(nameBytes, (int)position, (int)nameLengthBytes);
        }

        public static int BY_LOCAL_FILE_HEADER_OFFSET_COMPARATOR(CentralDirectoryRecord r1, CentralDirectoryRecord r2)
        {
            var offset1 = r1.LocalFileHeaderOffset;
            var offset2 = r2.LocalFileHeaderOffset;
            if (offset1 > offset2)
            {
                return 1;
            }
            else if (offset1 < offset2)
            {
                return -1;
            }
            else
            {
                return 0;
            }
        }

        public CentralDirectoryRecord CreateWithModifiedLocalFileHeaderOffset(
            long localFileHeaderOffset)
        {
            var result = new byte[Data.Length];
            Buffer.BlockCopy(Data, 0, result, 0, result.Length);

            var localFileHeaderOffsetBytes = BitConverter.GetBytes((uint)localFileHeaderOffset);
            Buffer.BlockCopy(localFileHeaderOffsetBytes, 0, result, LocalFileHeaderOffsetOffset,
                localFileHeaderOffsetBytes.Length);
            return new CentralDirectoryRecord(
                result,
                GpFlags,
                CompressionMethod,
                LastModificationTime,
                LastModificationDate,
                Crc32,
                CompressedSize,
                UncompressedSize,
                localFileHeaderOffset,
                Name,
                NameSizeBytes);
        }

        public static CentralDirectoryRecord CreateWithDeflateCompressedData(string name,
            int lastModifiedTime,
            int lastModifiedDate,
            long crc32,
            long compressedSize,
            long uncompressedSize,
            long localFileHeaderOffset)
        {
            var nameBytes = Encoding.UTF8.GetBytes(name);
            var gpFlags = ZipUtils.GpFlagEfs; // UTF-8 character encoding used for entry name
            var compressionMethod = ZipUtils.CompressionMethodDeflated;
            var recordSize = HeaderSizeBytes + nameBytes.Length;
            var result = new BinaryWriter(new MemoryStream(recordSize));
            result.Write(RecordSignature);
            result.Write((ushort)0x14); // Version made by
            result.Write((ushort)0x14); // Minimum version needed to extract
            result.Write(gpFlags);
            result.Write(compressionMethod);
            result.Write((ushort)lastModifiedTime);
            result.Write((ushort)lastModifiedDate);
            result.Write((uint)crc32);
            result.Write((uint)compressedSize);
            result.Write((uint)uncompressedSize);
            result.Write((ushort)nameBytes.Length);
            result.Write((ushort)0); // Extra field length
            result.Write((ushort)0); // File comment length
            result.Write((ushort)0); // Disk number
            result.Write((ushort)0); // Internal file attributes
            result.Write((uint)0); // External file attributes
            result.Write((uint)localFileHeaderOffset);
            result.Write(nameBytes);

            
            return new CentralDirectoryRecord(
                ((MemoryStream)result.BaseStream).ToArray(),
                gpFlags,
                compressionMethod,
                lastModifiedTime,
                lastModifiedDate,
                crc32,
                compressedSize,
                uncompressedSize,
                localFileHeaderOffset,
                name,
                nameBytes.Length);
        }

        public void CopyTo(Stream output)
        {
            output.Write(Data, 0, Data.Length);
        }
    }
}