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
using SigningServer.Android.Util;

namespace SigningServer.Android.Apk
{
    /// <summary>
    /// APK Signature Scheme v2 verifier.
    /// </summary>
    /// <remarks>
    /// APK Signature Scheme v2 is a whole-file signature scheme which aims to protect every single
    /// bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
    /// uncompressed contents of ZIP entries.
    /// <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2</a>
    /// </remarks>
    class V2SchemeVerifier
    {
        private const long ApkSigBlockMagicHi = 0x3234206b636f6c42L;
        private const long ApkSigBlockMagicLo = 0x20676953204b5041L;
        private const int ApkSigBlockMinSize = 32;

        /// <summary>
        /// Returns the APK Signing Block and its offset in the provided APK.
        /// </summary>
        /// <param name="apk"></param>
        /// <param name="zipSections"></param>
        /// <returns></returns>
        public static Tuple<DataSource, long> FindApkSigningBlock(DataSource apk, ApkUtils.ZipSections zipSections)
        {
            // FORMAT:
            // OFFSET       DATA TYPE  DESCRIPTION
            // * @+0  bytes uint64:    size in bytes (excluding this field)
            // * @+8  bytes payload
            // * @-24 bytes uint64:    size in bytes (same as the one above)
            // * @-16 bytes uint128:   magic
            long centralDirStartOffset = zipSections.CentralDirectoryOffset;
            var centralDirEndOffset =
                centralDirStartOffset + zipSections.CentralDirectorySizeBytes;
            var eocdStartOffset = zipSections.EndOfCentralDirectoryOffset;
            if (centralDirEndOffset != eocdStartOffset)
            {
                return null;
            }
            if (centralDirStartOffset < ApkSigBlockMinSize)
            {
                return null;
            }
            // Read the magic and offset in file from the footer section of the block:
            // * uint64:   size of block
            // * 16 bytes: magic
            var footer = apk.GetByteBuffer(centralDirEndOffset - 24, 24);
            if ((BitConverter.ToInt64(footer, 8) != ApkSigBlockMagicLo) || (BitConverter.ToInt64(footer, 16) != ApkSigBlockMagicHi))
            {
                return null;
            }
            // Read and compare size fields
            var apkSigBlockSizeInFooter = BitConverter.ToInt64(footer, 0);
            if ((apkSigBlockSizeInFooter < footer.Length) || (apkSigBlockSizeInFooter > int.MaxValue - 8))
            {
                return null;
            }
            var totalSize = (int)(apkSigBlockSizeInFooter + 8);
            var apkSigBlockOffset = centralDirStartOffset - totalSize;
            if (apkSigBlockOffset < 0)
            {
                return null;
            }

            var apkSigBlock = apk.GetByteBuffer(apkSigBlockOffset, 8);

            var apkSigBlockSizeInHeader = BitConverter.ToInt64(apkSigBlock, 8);
            if (apkSigBlockSizeInHeader != apkSigBlockSizeInFooter)
            {
                return null;
            }

            return Tuple.Create(apk.Slice(apkSigBlockOffset, totalSize), apkSigBlockOffset);
        }
    }
}