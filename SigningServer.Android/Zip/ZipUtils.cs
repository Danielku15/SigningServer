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
using Force.Crc32;
using Org.BouncyCastle.Utilities.Zlib;
using SigningServer.Android.Util;

namespace SigningServer.Android.Zip
{
    /// <summary>
    /// Assorted ZIP format helpers.
    /// </summary>
    static class ZipUtils
    {
        private const int ZipEocdRecMinSize = 22;
        private const int ZipEocdRecSig = 0x06054b50;
        private const int ZipEocdCentralDirTotalRecordCountOffset = 10;
        private const int ZipEocdCentralDirSizeFieldOffset = 12;
        private const int ZipEocdCentralDirOffsetFieldOffset = 16;
        private const int ZipEocdCommentLengthFieldOffset = 20;

        public const short GpFlagDataDescriptorUsed = 0x08;
        public const short GpFlagEfs = 0x0800;

        public const short CompressionMethodStored = 0;
        public const short CompressionMethodDeflated = 8;

        /// <summary>
        /// Returns the ZIP End of Central Directory record of the provided ZIP file.
        /// </summary>
        /// <param name="zip"></param>
        /// <returns>
        /// contents of the ZIP End of Central Directory record and the record's offset in the
        /// file or { @code null} if the file does not contain the record.
        /// </returns>
        public static Tuple<byte[], long> FindZipEndOfCentralDirectoryRecord(DataSource zip)
        {
            // ZIP End of Central Directory (EOCD) record is located at the very end of the ZIP archive.
            // The record can be identified by its 4-byte signature/magic which is located at the very
            // beginning of the record. A complication is that the record is variable-length because of
            // the comment field.
            // The algorithm for locating the ZIP EOCD record is as follows. We search backwards from
            // end of the buffer for the EOCD record signature. Whenever we find a signature, we check
            // the candidate record's comment length is such that the remainder of the record takes up
            // exactly the remaining bytes in the buffer. The search is bounded because the maximum
            // size of the comment field is 65535 bytes because the field is an unsigned 16-bit number.

            var fileSize = zip.Length;
            if (fileSize < ZipEocdRecMinSize)
            {
                return null;
            }

            // Optimization: 99.99% of APKs have a zero-length comment field in the EoCD record and thus
            // the EoCD record offset is known in advance. Try that offset first to avoid unnecessarily
            // reading more data.
            var result = FindZipEndOfCentralDirectoryRecord(zip, 0);
            if (result != null)
            {
                return result;
            }

            // EoCD does not start where we expected it to. Perhaps it contains a non-empty comment
            // field. Expand the search. The maximum size of the comment field in EoCD is 65535 because
            // the comment length field is an unsigned 16-bit number.
            return FindZipEndOfCentralDirectoryRecord(zip, UInt16.MaxValue);
        }

        /// <summary>
        /// Returns the ZIP End of Central Directory record of the provided ZIP file.
        /// </summary>
        /// <param name="zip"></param>
        /// <param name="maxCommentSize">
        /// maximum accepted size (in bytes) of EoCD comment field. The permitted
        /// value is from 0 to 65535 inclusive.The smaller the value, the faster this method
        /// locates the record, provided its comment field is no longer than this value.
        /// </param>
        /// <returns>
        /// contents of the ZIP End of Central Directory record and the record's offset in the
        /// file or { @code null} if the file does not contain the record.
        /// </returns>
        private static Tuple<byte[], long> FindZipEndOfCentralDirectoryRecord(DataSource zip, int maxCommentSize)
        {
            // ZIP End of Central Directory (EOCD) record is located at the very end of the ZIP archive.
            // The record can be identified by its 4-byte signature/magic which is located at the very
            // beginning of the record. A complication is that the record is variable-length because of
            // the comment field.
            // The algorithm for locating the ZIP EOCD record is as follows. We search backwards from
            // end of the buffer for the EOCD record signature. Whenever we find a signature, we check
            // the candidate record's comment length is such that the remainder of the record takes up
            // exactly the remaining bytes in the buffer. The search is bounded because the maximum
            // size of the comment field is 65535 bytes because the field is an unsigned 16-bit number.

            if ((maxCommentSize < 0) || (maxCommentSize > UInt16.MaxValue))
            {
                throw new ArgumentOutOfRangeException(nameof(maxCommentSize), maxCommentSize, $"max value: {UInt16.MaxValue}");
            }


            var fileSize = zip.Length;
            if (fileSize < ZipEocdRecMinSize)
            {
                // No space for EoCD record in the file.
                return null;
            }
            // Lower maxCommentSize if the file is too small.
            maxCommentSize = (int)Math.Min(maxCommentSize, fileSize - ZipEocdRecMinSize);
            var maxEocdSize = ZipEocdRecMinSize + maxCommentSize;
            var bufOffsetInFile = fileSize - maxEocdSize;

            var buf = zip.GetByteBuffer(bufOffsetInFile, maxEocdSize);

            var eocdOffsetInBuf = FindZipEndOfCentralDirectoryRecord(buf);
            if (eocdOffsetInBuf == -1)
            {
                // No EoCD record found in the buffer
                return null;
            }

            // EoCD found
            var eocd = buf.Slice(eocdOffsetInBuf);
            return Tuple.Create(eocd, bufOffsetInFile + eocdOffsetInBuf);
        }

        /// <summary>
        /// Returns the position at which ZIP End of Central Directory record starts in the provided
        /// buffer or { @code -1} if the record is not present.
        /// </summary>
        /// <param name="zipContents"></param>
        /// <returns></returns>
        private static int FindZipEndOfCentralDirectoryRecord(byte[] zipContents)
        {
            // ZIP End of Central Directory (EOCD) record is located at the very end of the ZIP archive.
            // The record can be identified by its 4-byte signature/magic which is located at the very
            // beginning of the record. A complication is that the record is variable-length because of
            // the comment field.
            // The algorithm for locating the ZIP EOCD record is as follows. We search backwards from
            // end of the buffer for the EOCD record signature. Whenever we find a signature, we check
            // the candidate record's comment length is such that the remainder of the record takes up
            // exactly the remaining bytes in the buffer. The search is bounded because the maximum
            // size of the comment field is 65535 bytes because the field is an unsigned 16-bit number.

            var archiveSize = zipContents.Length;
            if (archiveSize < ZipEocdRecMinSize)
            {
                return -1;
            }
            var maxCommentLength = Math.Min(archiveSize - ZipEocdRecMinSize, UInt16.MaxValue);
            var eocdWithEmptyCommentStartPosition = archiveSize - ZipEocdRecMinSize;
            for (var expectedCommentLength = 0; expectedCommentLength <= maxCommentLength;
                expectedCommentLength++)
            {
                var eocdStartPos = eocdWithEmptyCommentStartPosition - expectedCommentLength;
                if (BitConverter.ToInt32(zipContents, eocdStartPos) == ZipEocdRecSig)
                {
                    int actualCommentLength = BitConverter.ToUInt16(zipContents, eocdStartPos + ZipEocdCommentLengthFieldOffset);
                    if (actualCommentLength == expectedCommentLength)
                    {
                        return eocdStartPos;
                    }
                }
            }
            return -1;
        }

        /// <summary>
        /// Returns the offset of the start of the ZIP Central Directory in the archive.
        /// </summary>
        /// <param name="zipEndOfCentralDirectory"></param>
        /// <returns></returns>
        public static uint GetZipEocdCentralDirectoryOffset(byte[] zipEndOfCentralDirectory)
        {
            return BitConverter.ToUInt32(zipEndOfCentralDirectory, ZipEocdCentralDirOffsetFieldOffset);
        }

        /// <summary>
        /// Returns the size (in bytes) of the ZIP Central Directory.
        /// </summary>
        /// <param name="zipEndOfCentralDirectory"></param>
        /// <returns></returns>
        public static uint GetZipEocdCentralDirectorySizeBytes(byte[] zipEndOfCentralDirectory)
        {
            return BitConverter.ToUInt32(zipEndOfCentralDirectory, ZipEocdCentralDirSizeFieldOffset);
        }

        /// <summary>
        /// Returns the total number of records in ZIP Central Directory.
        /// </summary>
        /// <param name="zipEndOfCentralDirectory"></param>
        /// <returns></returns>
        public static ushort GetZipEocdCentralDirectoryTotalRecordCount(byte[] zipEndOfCentralDirectory)
        {
            return BitConverter.ToUInt16(zipEndOfCentralDirectory, ZipEocdCentralDirTotalRecordCountOffset);
        }

        /// <summary>
        /// Sets the offset of the start of the ZIP Central Directory in the archive.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="offset"></param>
        public static void SetZipEocdCentralDirectoryOffset(
            Stream stream, long offset)
        {
            var bytes = BitConverter.GetBytes((uint)offset);
            var pos = stream.Position;
            stream.Position = ZipEocdCentralDirOffsetFieldOffset;
            stream.Write(bytes, 0, bytes.Length);
            stream.Position = pos;
        }



        public static Tuple<byte[], uint> Deflate(byte[] input)
        {
            // ReSharper disable InconsistentNaming
            const int Z_OK = 0;
            const int Z_MEM_ERROR = -4;
            const int Z_STREAM_ERROR = -2;
            const int Z_FINISH = 4;
            const int Z_STREAM_END = 1;
            // ReSharper restore InconsistentNaming

            var crc32 = Crc32Algorithm.Compute(input);

            var result = new MemoryStream();

            var outputBuf = new byte[65536];
            var zstream = new ZStream();

            try
            {
                switch (zstream.deflateInit(9, true))
                {
                    case Z_OK:
                        break;
                    case Z_MEM_ERROR:
                        throw new OutOfMemoryException("zlib ran out of memory");
                    case Z_STREAM_ERROR:
                        throw new ArgumentException();
                    default:
                        throw new InvalidOperationException(zstream.msg);
                }

                zstream.next_in = input;
                zstream.next_in_index = 0;
                zstream.avail_in = input.Length;

                do
                {
                    zstream.next_out = outputBuf;
                    zstream.next_out_index = 0;
                    zstream.avail_out = outputBuf.Length;
                    switch (zstream.deflate(Z_FINISH))
                    {
                        case Z_OK:
                        case Z_STREAM_END:
                            var count = outputBuf.Length - zstream.avail_out;
                            if (count > 0)
                            {
                                result.Write(outputBuf, 0, count);
                            }
                            continue;
                        default:
                            throw new IOException("deflating: " + zstream.msg);
                    }
                }
                while (zstream.avail_in > 0 || zstream.avail_out == 0);

                return Tuple.Create(result.ToArray(), crc32);
            }
            finally
            {
                zstream.free();
            }
        }
    }
}