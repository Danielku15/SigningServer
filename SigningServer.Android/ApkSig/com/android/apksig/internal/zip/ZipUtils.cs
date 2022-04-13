// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Zip
{
    /// <summary>
    /// Assorted ZIP format helpers.
    /// 
    /// &lt;p&gt;NOTE: Most helper methods operating on {@code ByteBuffer} instances expect that the byte
    /// order of these buffers is little-endian.
    /// </summary>
    public abstract class ZipUtils
    {
        internal ZipUtils()
        {
        }
        
        public static readonly short COMPRESSION_METHOD_STORED = 0;
        
        public static readonly short COMPRESSION_METHOD_DEFLATED = 8;
        
        public static readonly short GP_FLAG_DATA_DESCRIPTOR_USED = 0x08;
        
        public static readonly short GP_FLAG_EFS = 0x0800;
        
        internal static readonly int ZIP_EOCD_REC_MIN_SIZE = 22;
        
        internal static readonly int ZIP_EOCD_REC_SIG = 0x06054b50;
        
        internal static readonly int ZIP_EOCD_CENTRAL_DIR_TOTAL_RECORD_COUNT_OFFSET = 10;
        
        internal static readonly int ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12;
        
        internal static readonly int ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16;
        
        internal static readonly int ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20;
        
        internal static readonly int UINT16_MAX_VALUE = 0xffff;
        
        /// <summary>
        /// Sets the offset of the start of the ZIP Central Directory in the archive.
        /// 
        /// &lt;p&gt;NOTE: Byte order of {@code zipEndOfCentralDirectory} must be little-endian.
        /// </summary>
        public static void SetZipEocdCentralDirectoryOffset(SigningServer.Android.IO.ByteBuffer zipEndOfCentralDirectory, long offset)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.AssertByteOrderLittleEndian(zipEndOfCentralDirectory);
            SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.SetUnsignedInt32(zipEndOfCentralDirectory, zipEndOfCentralDirectory.Position() + SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET, offset);
        }
        
        /// <summary>
        /// Returns the offset of the start of the ZIP Central Directory in the archive.
        /// 
        /// &lt;p&gt;NOTE: Byte order of {@code zipEndOfCentralDirectory} must be little-endian.
        /// </summary>
        public static long GetZipEocdCentralDirectoryOffset(SigningServer.Android.IO.ByteBuffer zipEndOfCentralDirectory)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.AssertByteOrderLittleEndian(zipEndOfCentralDirectory);
            return SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.GetUnsignedInt32(zipEndOfCentralDirectory, zipEndOfCentralDirectory.Position() + SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET);
        }
        
        /// <summary>
        /// Returns the size (in bytes) of the ZIP Central Directory.
        /// 
        /// &lt;p&gt;NOTE: Byte order of {@code zipEndOfCentralDirectory} must be little-endian.
        /// </summary>
        public static long GetZipEocdCentralDirectorySizeBytes(SigningServer.Android.IO.ByteBuffer zipEndOfCentralDirectory)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.AssertByteOrderLittleEndian(zipEndOfCentralDirectory);
            return SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.GetUnsignedInt32(zipEndOfCentralDirectory, zipEndOfCentralDirectory.Position() + SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET);
        }
        
        /// <summary>
        /// Returns the total number of records in ZIP Central Directory.
        /// 
        /// &lt;p&gt;NOTE: Byte order of {@code zipEndOfCentralDirectory} must be little-endian.
        /// </summary>
        public static int GetZipEocdCentralDirectoryTotalRecordCount(SigningServer.Android.IO.ByteBuffer zipEndOfCentralDirectory)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.AssertByteOrderLittleEndian(zipEndOfCentralDirectory);
            return SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.GetUnsignedInt16(zipEndOfCentralDirectory, zipEndOfCentralDirectory.Position() + SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_CENTRAL_DIR_TOTAL_RECORD_COUNT_OFFSET);
        }
        
        /// <summary>
        /// Returns the ZIP End of Central Directory record of the provided ZIP file.
        /// 
        /// @return contents of the ZIP End of Central Directory record and the record's offset in the
        ///         file or {@code null} if the file does not contain the record.
        /// @throws IOException if an I/O error occurs while reading the file.
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<SigningServer.Android.IO.ByteBuffer, long?> FindZipEndOfCentralDirectoryRecord(SigningServer.Android.Com.Android.Apksig.Util.DataSource zip)
        {
            long fileSize = zip.Size();
            if (fileSize < SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_REC_MIN_SIZE)
            {
                return null;
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<SigningServer.Android.IO.ByteBuffer, long?> result = SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.FindZipEndOfCentralDirectoryRecord(zip, 0);
            if (result != null)
            {
                return result;
            }
            return SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.FindZipEndOfCentralDirectoryRecord(zip, SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.UINT16_MAX_VALUE);
        }
        
        /// <summary>
        /// Returns the ZIP End of Central Directory record of the provided ZIP file.
        /// 
        /// @param maxCommentSize maximum accepted size (in bytes) of EoCD comment field. The permitted
        ///        value is from 0 to 65535 inclusive. The smaller the value, the faster this method
        ///        locates the record, provided its comment field is no longer than this value.
        /// @return contents of the ZIP End of Central Directory record and the record's offset in the
        ///         file or {@code null} if the file does not contain the record.
        /// @throws IOException if an I/O error occurs while reading the file.
        /// </summary>
        internal static SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<SigningServer.Android.IO.ByteBuffer, long?> FindZipEndOfCentralDirectoryRecord(SigningServer.Android.Com.Android.Apksig.Util.DataSource zip, int maxCommentSize)
        {
            if ((maxCommentSize < 0) || (maxCommentSize > SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.UINT16_MAX_VALUE))
            {
                throw new System.ArgumentException("maxCommentSize: " + maxCommentSize);
            }
            long fileSize = zip.Size();
            if (fileSize < SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_REC_MIN_SIZE)
            {
                return null;
            }
            maxCommentSize = (int)SigningServer.Android.Core.Math.Min(maxCommentSize, fileSize - SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_REC_MIN_SIZE);
            int maxEocdSize = SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_REC_MIN_SIZE + maxCommentSize;
            long bufOffsetInFile = fileSize - maxEocdSize;
            SigningServer.Android.IO.ByteBuffer buf = zip.GetByteBuffer(bufOffsetInFile, maxEocdSize);
            buf.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            int eocdOffsetInBuf = SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.FindZipEndOfCentralDirectoryRecord(buf);
            if (eocdOffsetInBuf == -1)
            {
                return null;
            }
            buf.Position(eocdOffsetInBuf);
            SigningServer.Android.IO.ByteBuffer eocd = buf.Slice();
            eocd.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            return SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<SigningServer.Android.IO.ByteBuffer, long>(eocd, bufOffsetInFile + eocdOffsetInBuf);
        }
        
        /// <summary>
        /// Returns the position at which ZIP End of Central Directory record starts in the provided
        /// buffer or {@code -1} if the record is not present.
        /// 
        /// &lt;p&gt;NOTE: Byte order of {@code zipContents} must be little-endian.
        /// </summary>
        internal static int FindZipEndOfCentralDirectoryRecord(SigningServer.Android.IO.ByteBuffer zipContents)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.AssertByteOrderLittleEndian(zipContents);
            int archiveSize = zipContents.Capacity();
            if (archiveSize < SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_REC_MIN_SIZE)
            {
                return -1;
            }
            int maxCommentLength = SigningServer.Android.Core.Math.Min(archiveSize - SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_REC_MIN_SIZE, SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.UINT16_MAX_VALUE);
            int eocdWithEmptyCommentStartPosition = archiveSize - SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_REC_MIN_SIZE;
            for (int expectedCommentLength = 0;expectedCommentLength <= maxCommentLength;expectedCommentLength++)
            {
                int eocdStartPos = eocdWithEmptyCommentStartPosition - expectedCommentLength;
                if (zipContents.GetInt(eocdStartPos) == SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_REC_SIG)
                {
                    int actualCommentLength = SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.GetUnsignedInt16(zipContents, eocdStartPos + SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET);
                    if (actualCommentLength == expectedCommentLength)
                    {
                        return eocdStartPos;
                    }
                }
            }
            return -1;
        }
        
        public static void AssertByteOrderLittleEndian(SigningServer.Android.IO.ByteBuffer buffer)
        {
            if (buffer.Order() != SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN)
            {
                throw new System.ArgumentException("ByteBuffer byte order must be little endian");
            }
        }
        
        public static int GetUnsignedInt16(SigningServer.Android.IO.ByteBuffer buffer, int offset)
        {
            return buffer.GetShort(offset) & 0xffff;
        }
        
        public static int GetUnsignedInt16(SigningServer.Android.IO.ByteBuffer buffer)
        {
            return buffer.GetShort() & 0xffff;
        }
        
        public static SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Zip.CentralDirectoryRecord> ParseZipCentralDirectory(SigningServer.Android.Com.Android.Apksig.Util.DataSource apk, SigningServer.Android.Com.Android.Apksig.Zip.ZipSections apkSections)
        {
            long cdSizeBytes = apkSections.GetZipCentralDirectorySizeBytes();
            if (cdSizeBytes > SigningServer.Android.Core.IntExtensions.MaxValue)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("ZIP Central Directory too large: " + cdSizeBytes);
            }
            long cdOffset = apkSections.GetZipCentralDirectoryOffset();
            SigningServer.Android.IO.ByteBuffer cd = apk.GetByteBuffer(cdOffset, (int)cdSizeBytes);
            cd.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            int expectedCdRecordCount = apkSections.GetZipCentralDirectoryRecordCount();
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Zip.CentralDirectoryRecord> cdRecords = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Zip.CentralDirectoryRecord>(expectedCdRecordCount);
            for (int i = 0;i < expectedCdRecordCount;i++)
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Zip.CentralDirectoryRecord cdRecord;
                int offsetInsideCd = cd.Position();
                try
                {
                    cdRecord = SigningServer.Android.Com.Android.Apksig.Internal.Zip.CentralDirectoryRecord.GetRecord(cd);
                }
                catch (SigningServer.Android.Com.Android.Apksig.Zip.ZipFormatException e)
                {
                    throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Malformed ZIP Central Directory record #" + (i + 1) + " at file offset " + (cdOffset + offsetInsideCd), e);
                }
                string entryName = cdRecord.GetName();
                if (entryName.EndsWith("/"))
                {
                    continue;
                }
                cdRecords.Add(cdRecord);
            }
            return cdRecords;
        }
        
        public static void SetUnsignedInt16(SigningServer.Android.IO.ByteBuffer buffer, int offset, int value)
        {
            if ((value < 0) || (value > 0xffff))
            {
                throw new System.ArgumentException("uint16 value of out range: " + value);
            }
            buffer.PutShort(offset, (short)value);
        }
        
        public static void SetUnsignedInt32(SigningServer.Android.IO.ByteBuffer buffer, int offset, long value)
        {
            if ((value < 0) || (value > 0xffffffffL))
            {
                throw new System.ArgumentException("uint32 value of out range: " + value);
            }
            buffer.PutInt(offset, (int)value);
        }
        
        public static void PutUnsignedInt16(SigningServer.Android.IO.ByteBuffer buffer, int value)
        {
            if ((value < 0) || (value > 0xffff))
            {
                throw new System.ArgumentException("uint16 value of out range: " + value);
            }
            buffer.PutShort((short)value);
        }
        
        public static long GetUnsignedInt32(SigningServer.Android.IO.ByteBuffer buffer, int offset)
        {
            return buffer.GetInt(offset) & 0xffffffffL;
        }
        
        public static long GetUnsignedInt32(SigningServer.Android.IO.ByteBuffer buffer)
        {
            return buffer.GetInt() & 0xffffffffL;
        }
        
        public static void PutUnsignedInt32(SigningServer.Android.IO.ByteBuffer buffer, long value)
        {
            if ((value < 0) || (value > 0xffffffffL))
            {
                throw new System.ArgumentException("uint32 value of out range: " + value);
            }
            buffer.PutInt((int)value);
        }
        
        public static SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.DeflateResult Deflate(SigningServer.Android.IO.ByteBuffer input)
        {
            sbyte[] inputBuf;
            int inputOffset;
            int inputLength = input.Remaining();
            if (input.HasArray())
            {
                inputBuf = input.Array();
                inputOffset = input.ArrayOffset() + input.Position();
                input.Position(input.Limit());
            }
            else 
            {
                inputBuf = new sbyte[inputLength];
                inputOffset = 0;
                input.Get(inputBuf);
            }
            SigningServer.Android.Util.Zip.CRC32 crc32 = new SigningServer.Android.Util.Zip.CRC32();
            crc32.Update(inputBuf, inputOffset, inputLength);
            long crc32Value = crc32.GetValue();
            SigningServer.Android.IO.ByteArrayOutputStream output = new SigningServer.Android.IO.ByteArrayOutputStream();
            SigningServer.Android.Util.Zip.Deflater deflater = new SigningServer.Android.Util.Zip.Deflater(9, true);
            deflater.SetInput(inputBuf, inputOffset, inputLength);
            deflater.Finish();
            sbyte[] buf = new sbyte[65536];
            while (!deflater.Finished())
            {
                int chunkSize = deflater.Deflate(buf);
                output.Write(buf, 0, chunkSize);
            }
            return new SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.DeflateResult(inputLength, crc32Value, output.ToByteArray());
        }
        
        public class DeflateResult
        {
            public readonly int inputSizeBytes;
            
            public readonly long inputCrc32;
            
            public readonly sbyte[] output;
            
            public DeflateResult(int inputSizeBytes, long inputCrc32, sbyte[] output)
            {
                this.inputSizeBytes = inputSizeBytes;
                this.inputCrc32 = inputCrc32;
                this.output = output;
            }
            
        }
        
    }
    
}
