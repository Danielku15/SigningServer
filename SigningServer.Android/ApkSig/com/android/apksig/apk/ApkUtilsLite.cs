// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Apk
{
    /// <summary>
    /// Lightweight version of the ApkUtils for clients that only require a subset of the utility
    /// functionality.
    /// </summary>
    public class ApkUtilsLite
    {
        internal ApkUtilsLite()
        {
        }
        
        /// <summary>
        /// Finds the main ZIP sections of the provided APK.
        /// 
        /// @throws IOException if an I/O error occurred while reading the APK
        /// @throws ZipFormatException if the APK is malformed
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Zip.ZipSections FindZipSections(SigningServer.Android.Com.Android.Apksig.Util.DataSource apk)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<SigningServer.Android.IO.ByteBuffer, long?> eocdAndOffsetInFile = SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.FindZipEndOfCentralDirectoryRecord(apk);
            if (eocdAndOffsetInFile == null)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Zip.ZipFormatException("ZIP End of Central Directory record not found");
            }
            SigningServer.Android.IO.ByteBuffer eocdBuf = eocdAndOffsetInFile.GetFirst();
            long eocdOffset = eocdAndOffsetInFile.GetSecond();
            eocdBuf.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            long cdStartOffset = SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.GetZipEocdCentralDirectoryOffset(eocdBuf);
            if (cdStartOffset > eocdOffset)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Zip.ZipFormatException("ZIP Central Directory start offset out of range: " + cdStartOffset + ". ZIP End of Central Directory offset: " + eocdOffset);
            }
            long cdSizeBytes = SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.GetZipEocdCentralDirectorySizeBytes(eocdBuf);
            long cdEndOffset = cdStartOffset + cdSizeBytes;
            if (cdEndOffset > eocdOffset)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Zip.ZipFormatException("ZIP Central Directory overlaps with End of Central Directory" + ". CD end: " + cdEndOffset + ", EoCD start: " + eocdOffset);
            }
            int cdRecordCount = SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.GetZipEocdCentralDirectoryTotalRecordCount(eocdBuf);
            return new SigningServer.Android.Com.Android.Apksig.Zip.ZipSections(cdStartOffset, cdSizeBytes, cdRecordCount, eocdOffset, eocdBuf);
        }
        
        internal static readonly long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L;
        
        internal static readonly long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L;
        
        internal static readonly int APK_SIG_BLOCK_MIN_SIZE = 32;
        
        /// <summary>
        /// Returns the APK Signing Block of the provided APK.
        /// 
        /// @throws IOException if an I/O error occurs
        /// @throws ApkSigningBlockNotFoundException if there is no APK Signing Block in the APK
        /// @see &lt;a href="https://source.android.com/security/apksigning/v2.html"&gt;APK Signature Scheme v2
        /// &lt;/a&gt;
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.ApkSigningBlock FindApkSigningBlock(SigningServer.Android.Com.Android.Apksig.Util.DataSource apk, SigningServer.Android.Com.Android.Apksig.Zip.ZipSections zipSections)
        {
            long centralDirStartOffset = zipSections.GetZipCentralDirectoryOffset();
            long centralDirEndOffset = centralDirStartOffset + zipSections.GetZipCentralDirectorySizeBytes();
            long eocdStartOffset = zipSections.GetZipEndOfCentralDirectoryOffset();
            if (centralDirEndOffset != eocdStartOffset)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkSigningBlockNotFoundException("ZIP Central Directory is not immediately followed by End of Central Directory" + ". CD end: " + centralDirEndOffset + ", EoCD start: " + eocdStartOffset);
            }
            if (centralDirStartOffset < SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.APK_SIG_BLOCK_MIN_SIZE)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkSigningBlockNotFoundException("APK too small for APK Signing Block. ZIP Central Directory offset: " + centralDirStartOffset);
            }
            SigningServer.Android.IO.ByteBuffer footer = apk.GetByteBuffer(centralDirStartOffset - 24, 24);
            footer.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            if ((footer.GetLong(8) != SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.APK_SIG_BLOCK_MAGIC_LO) || (footer.GetLong(16) != SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.APK_SIG_BLOCK_MAGIC_HI))
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkSigningBlockNotFoundException("No APK Signing Block before ZIP Central Directory");
            }
            long apkSigBlockSizeInFooter = footer.GetLong(0);
            if ((apkSigBlockSizeInFooter < footer.Capacity()) || (apkSigBlockSizeInFooter > SigningServer.Android.Core.IntExtensions.MaxValue - 8))
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkSigningBlockNotFoundException("APK Signing Block size out of range: " + apkSigBlockSizeInFooter);
            }
            int totalSize = (int)(apkSigBlockSizeInFooter + 8);
            long apkSigBlockOffset = centralDirStartOffset - totalSize;
            if (apkSigBlockOffset < 0)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkSigningBlockNotFoundException("APK Signing Block offset out of range: " + apkSigBlockOffset);
            }
            SigningServer.Android.IO.ByteBuffer apkSigBlock = apk.GetByteBuffer(apkSigBlockOffset, 8);
            apkSigBlock.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            long apkSigBlockSizeInHeader = apkSigBlock.GetLong(0);
            if (apkSigBlockSizeInHeader != apkSigBlockSizeInFooter)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkSigningBlockNotFoundException("APK Signing Block sizes in header and footer do not match: " + apkSigBlockSizeInHeader + " vs " + apkSigBlockSizeInFooter);
            }
            return new SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.ApkSigningBlock(apkSigBlockOffset, apk.Slice(apkSigBlockOffset, totalSize));
        }
        
        /// <summary>
        /// Information about the location of the APK Signing Block inside an APK.
        /// </summary>
        public class ApkSigningBlock
        {
            internal readonly long mStartOffsetInApk;
            
            internal readonly SigningServer.Android.Com.Android.Apksig.Util.DataSource mContents;
            
            /// <summary>
            /// Constructs a new {@code ApkSigningBlock}.
            /// 
            /// @param startOffsetInApk start offset (in bytes, relative to start of file) of the APK
            ///        Signing Block inside the APK file
            /// @param contents contents of the APK Signing Block
            /// </summary>
            public ApkSigningBlock(long startOffsetInApk, SigningServer.Android.Com.Android.Apksig.Util.DataSource contents)
            {
                mStartOffsetInApk = startOffsetInApk;
                mContents = contents;
            }
            
            /// <summary>
            /// Returns the start offset (in bytes, relative to start of file) of the APK Signing Block.
            /// </summary>
            public virtual long GetStartOffset()
            {
                return mStartOffsetInApk;
            }
            
            /// <summary>
            /// Returns the data source which provides the full contents of the APK Signing Block,
            /// including its footer.
            /// </summary>
            public virtual SigningServer.Android.Com.Android.Apksig.Util.DataSource GetContents()
            {
                return mContents;
            }
            
        }
        
        public static sbyte[] ComputeSha256DigestBytes(sbyte[] data)
        {
            SigningServer.Android.Security.MessageDigest messageDigest;
            try
            {
                messageDigest = SigningServer.Android.Security.MessageDigest.GetInstance("SHA-256");
            }
            catch (SigningServer.Android.Security.NoSuchAlgorithmException e)
            {
                throw new System.InvalidOperationException("SHA-256 is not found", e);
            }
            messageDigest.Update(data);
            return messageDigest.Digest();
        }
        
    }
    
}
