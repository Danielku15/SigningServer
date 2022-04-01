/*
 * Copyright (C) 2020 The Android Open Source Project
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
using System.Text;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;

namespace SigningServer.Android.ApkSig.Internal.Apk
{
    /**
     * Lightweight version of the ApkSigningBlockUtils for clients that only require a subset of the
     * utility functionality.
     */
    public static class ApkSigningBlockUtilsLite
    {
        private static readonly char[] HEX_DIGITS = "0123456789abcdef".ToCharArray();

        /**
         * Returns the APK Signature Scheme block contained in the provided APK file for the given ID
         * and the additional information relevant for verifying the block against the file.
         *
         * @param blockId the ID value in the APK Signing Block's sequence of ID-value pairs
         *                identifying the appropriate block to find, e.g. the APK Signature Scheme v2
         *                block ID.
         *
         * @throws SignatureNotFoundException if the APK is not signed using given APK Signature Scheme
         * @throws IOException if an I/O error occurs while reading the APK
         */
        public static SignatureInfo findSignature(
            DataSource apk, ZipSections zipSections, int blockId)

        {
            // Find the APK Signing Block.
            DataSource apkSigningBlock;
            long apkSigningBlockOffset;
            try
            {
                ApkUtilsLite.ApkSigningBlock apkSigningBlockInfo =
                    ApkUtilsLite.findApkSigningBlock(apk, zipSections);
                apkSigningBlockOffset = apkSigningBlockInfo.getStartOffset();
                apkSigningBlock = apkSigningBlockInfo.getContents();
            }
            catch (ApkSigningBlockNotFoundException e)
            {
                throw new SignatureNotFoundException(e.Message, e);
            }

            ByteBuffer apkSigningBlockBuf =
                apkSigningBlock.getByteBuffer(0, (int)apkSigningBlock.size());
            apkSigningBlockBuf.order(ByteOrder.LITTLE_ENDIAN);

            // Find the APK Signature Scheme Block inside the APK Signing Block.
            ByteBuffer apkSignatureSchemeBlock =
                findApkSignatureSchemeBlock(apkSigningBlockBuf, blockId);
            return new SignatureInfo(
                apkSignatureSchemeBlock,
                apkSigningBlockOffset,
                zipSections.getZipCentralDirectoryOffset(),
                zipSections.getZipEndOfCentralDirectoryOffset(),
                zipSections.getZipEndOfCentralDirectory());
        }

        public static ByteBuffer findApkSignatureSchemeBlock(
            ByteBuffer apkSigningBlock,
            int blockId)
        {
            checkByteOrderLittleEndian(apkSigningBlock);

            // FORMAT:
            // OFFSET       DATA TYPE  DESCRIPTION
            // * @+0  bytes uint64:    size in bytes (excluding this field)
            // * @+8  bytes pairs
            // * @-24 bytes uint64:    size in bytes (same as the one above)
            // * @-16 bytes uint128:   magic
            ByteBuffer pairs = sliceFromTo(apkSigningBlock, 8, apkSigningBlock.capacity() - 24);

            int entryCount = 0;
            while (pairs.hasRemaining())
            {
                entryCount++;
                if (pairs.remaining() < 8)
                {
                    throw new SignatureNotFoundException(
                        "Insufficient data to read size of APK Signing Block entry #" + entryCount);
                }

                long lenLong = pairs.getLong();
                if ((lenLong < 4) || (lenLong > int.MaxValue))
                {
                    throw new SignatureNotFoundException(
                        "APK Signing Block entry #" + entryCount
                                                    + " size out of range: " + lenLong);
                }

                int len = (int)lenLong;
                int nextEntryPos = pairs.position() + len;
                if (len > pairs.remaining())
                {
                    throw new SignatureNotFoundException(
                        "APK Signing Block entry #" + entryCount + " size out of range: " + len
                        + ", available: " + pairs.remaining());
                }

                int id = pairs.getInt();
                if (id == blockId)
                {
                    return getByteBuffer(pairs, len - 4);
                }

                pairs.position(nextEntryPos);
            }

            throw new SignatureNotFoundException(
                "No APK Signature Scheme block in APK Signing Block with ID: " + blockId);
        }

        public static void checkByteOrderLittleEndian(ByteBuffer buffer)
        {
            if (buffer.order() != ByteOrder.LITTLE_ENDIAN)
            {
                throw new ArgumentException("ByteBuffer byte order must be little endian");
            }
        }

        /**
         * Returns the subset of signatures which are expected to be verified by at least one Android
         * platform version in the {@code [minSdkVersion, maxSdkVersion]} range. The returned result is
         * guaranteed to contain at least one signature.
         *
         * <p>Each Android platform version typically verifies exactly one signature from the provided
         * {@code signatures} set. This method returns the set of these signatures collected over all
         * requested platform versions. As a result, the result may contain more than one signature.
         *
         * @throws NoApkSupportedSignaturesException if no supported signatures were
         *         found for an Android platform version in the range.
         */
        public static List<T> getSignaturesToVerify<T>(
            List<T> signatures, int minSdkVersion, int maxSdkVersion) where T : ApkSupportedSignature
        {
            return getSignaturesToVerify(signatures, minSdkVersion, maxSdkVersion, false);
        }

        /**
         * Returns the subset of signatures which are expected to be verified by at least one Android
         * platform version in the {@code [minSdkVersion, maxSdkVersion]} range. The returned result is
         * guaranteed to contain at least one signature.
         *
         * <p>{@code onlyRequireJcaSupport} can be set to true for cases that only require verifying a
         * signature within the signing block using the standard JCA.
         *
         * <p>Each Android platform version typically verifies exactly one signature from the provided
         * {@code signatures} set. This method returns the set of these signatures collected over all
         * requested platform versions. As a result, the result may contain more than one signature.
         *
         * @throws NoApkSupportedSignaturesException if no supported signatures were
         *         found for an Android platform version in the range.
         */
        public static List<T> getSignaturesToVerify<T>(
            List<T> signatures, int? minSdkVersion, int maxSdkVersion,
            bool onlyRequireJcaSupport) where T : ApkSupportedSignature
        {
            // Pick the signature with the strongest algorithm at all required SDK versions, to mimic
            // Android's behavior on those versions.
            //
            // Here we assume that, once introduced, a signature algorithm continues to be supported in
            // all future Android versions. We also assume that the better-than relationship between
            // algorithms is exactly the same on all Android platform versions (except that older
            // platforms might support fewer algorithms). If these assumption are no longer true, the
            // logic here will need to change accordingly.
            Dictionary<int, T> bestSigAlgorithmOnSdkVersion = new Dictionary<int, T>();
            int minProvidedSignaturesVersion = int.MaxValue;
            foreach (T sig in signatures)
            {
                SignatureAlgorithm sigAlgorithm = sig.algorithm;
                int sigMinSdkVersion = onlyRequireJcaSupport
                    ? sigAlgorithm.getJcaSigAlgMinSdkVersion()
                    : sigAlgorithm.getMinSdkVersion();
                if (sigMinSdkVersion > maxSdkVersion)
                {
                    continue;
                }

                if (sigMinSdkVersion < minProvidedSignaturesVersion)
                {
                    minProvidedSignaturesVersion = sigMinSdkVersion;
                }

                bestSigAlgorithmOnSdkVersion.TryGetValue(sigMinSdkVersion, out var candidate);
                if ((candidate == null)
                    || (compareSignatureAlgorithm(
                        sigAlgorithm, candidate.algorithm) > 0))
                {
                    bestSigAlgorithmOnSdkVersion[sigMinSdkVersion] = sig;
                }
            }

            // Must have some supported signature algorithms for minSdkVersion.
            if (minSdkVersion < minProvidedSignaturesVersion)
            {
                throw new NoApkSupportedSignaturesException(
                    "Minimum provided signature version " + minProvidedSignaturesVersion +
                    " > minSdkVersion " + minSdkVersion);
            }

            if (bestSigAlgorithmOnSdkVersion.Count == 0)
            {
                throw new NoApkSupportedSignaturesException("No supported signature");
            }

            List<T> signaturesToVerify = new List<T>(bestSigAlgorithmOnSdkVersion.Values);
            signaturesToVerify.Sort(
                (sig1, sig2) => sig1.algorithm.getId().CompareTo(sig2.algorithm.getId()));
            return signaturesToVerify;
        }

        /**
 * Returns positive number if {@code alg1} is preferred over {@code alg2}, {@code -1} if
 * {@code alg2} is preferred over {@code alg1}, and {@code 0} if there is no preference.
 */
        public static int compareSignatureAlgorithm(SignatureAlgorithm alg1, SignatureAlgorithm alg2)
        {
            ContentDigestAlgorithm digestAlg1 = alg1.getContentDigestAlgorithm();
            ContentDigestAlgorithm digestAlg2 = alg2.getContentDigestAlgorithm();
            return compareContentDigestAlgorithm(digestAlg1, digestAlg2);
        }

        /**
 * Returns a positive number if {@code alg1} is preferred over {@code alg2}, a negative number
 * if {@code alg2} is preferred over {@code alg1}, or {@code 0} if there is no preference.
 */
        private static int compareContentDigestAlgorithm(
            ContentDigestAlgorithm alg1,
            ContentDigestAlgorithm alg2)
        {
            if (alg1 == ContentDigestAlgorithm.CHUNKED_SHA256)
            {
                if (alg2 == ContentDigestAlgorithm.CHUNKED_SHA256)
                {
                    return 0;
                }

                if (alg2 == ContentDigestAlgorithm.CHUNKED_SHA512 ||
                    alg2 == ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)
                {
                    return -1;
                }

                throw new ArgumentException("Unknown alg2: " + alg2);
            }

            if (alg1 == ContentDigestAlgorithm.CHUNKED_SHA512)
            {
                if (alg2 == ContentDigestAlgorithm.CHUNKED_SHA256 ||
                    alg2 == ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)
                {
                    return 1;
                }

                if (alg2 == ContentDigestAlgorithm.CHUNKED_SHA512)
                {
                    return 0;
                }

                throw new ArgumentException("Unknown alg2: " + alg2);
            }

            if (alg1 == ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)
            {
                if (alg2 == ContentDigestAlgorithm.CHUNKED_SHA256)
                {
                    return 1;
                }

                if (alg2 == ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)
                {
                    return 0;
                }

                if (alg2 == ContentDigestAlgorithm.CHUNKED_SHA512)
                {
                    return -1;
                }

                throw new ArgumentException("Unknown alg2: " + alg2);
            }

            throw new ArgumentException("Unknown alg1: " + alg1);
        }

        /**
         * Returns new byte buffer whose content is a shared subsequence of this buffer's content
         * between the specified start (inclusive) and end (exclusive) positions. As opposed to
         * {@link ByteBuffer#slice()}, the returned buffer's byte order is the same as the source
         * buffer's byte order.
         */
        private static ByteBuffer sliceFromTo(ByteBuffer source, int start, int end)
        {
            if (start < 0)
            {
                throw new ArgumentException("start: " + start);
            }

            if (end < start)
            {
                throw new ArgumentException("end < start: " + end + " < " + start);
            }

            int capacity = source.capacity();
            if (end > source.capacity())
            {
                throw new ArgumentException("end > capacity: " + end + " > " + capacity);
            }

            int originalLimit = source.limit();
            int originalPosition = source.position();
            try
            {
                source.position(0);
                source.limit(end);
                source.position(start);
                ByteBuffer result = source.slice();
                result.order(source.order());
                return result;
            }
            finally
            {
                source.position(0);
                source.limit(originalLimit);
                source.position(originalPosition);
            }
        }

        /**
         * Relative <em>get</em> method for reading {@code size} number of bytes from the current
         * position of this buffer.
         *
         * <p>This method reads the next {@code size} bytes at this buffer's current position,
         * returning them as a {@code ByteBuffer} with start set to 0, limit and capacity set to
         * {@code size}, byte order set to this buffer's byte order; and then increments the position by
         * {@code size}.
         */
        private static ByteBuffer getByteBuffer(ByteBuffer source, int size)
        {
            if (size < 0)
            {
                throw new ArgumentException("size: " + size);
            }

            int originalLimit = source.limit();
            int position = source.position();
            int limit = position + size;
            if ((limit < position) || (limit > originalLimit))
            {
                throw new BufferUnderflowException();
            }

            source.limit(limit);
            try
            {
                ByteBuffer result = source.slice();
                result.order(source.order());
                source.position(limit);
                return result;
            }
            finally
            {
                source.limit(originalLimit);
            }
        }

        public static String toHex(byte[] value)
        {
            StringBuilder sb = new StringBuilder(value.Length * 2);
            int len = value.Length;
            for (int i = 0; i < len; i++)
            {
                int hi = (value[i] & 0xff) >> 4;
                int lo = value[i] & 0x0f;
                sb.Append(HEX_DIGITS[hi]).Append(HEX_DIGITS[lo]);
            }

            return sb.ToString();
        }

        public static ByteBuffer getLengthPrefixedSlice(ByteBuffer source)
        {
            if (source.remaining() < 4)
            {
                throw new ApkFormatException(
                    "Remaining buffer too short to contain length of length-prefixed field"
                    + ". Remaining: " + source.remaining());
            }

            int len = source.getInt();
            if (len < 0)
            {
                throw new ArgumentException("Negative length");
            }
            else if (len > source.remaining())
            {
                throw new ApkFormatException(
                    "Length-prefixed field longer than remaining buffer"
                    + ". Field length: " + len + ", remaining: " + source.remaining());
            }

            return getByteBuffer(source, len);
        }

        public static byte[] readLengthPrefixedByteArray(ByteBuffer buf)
        {
            int len = buf.getInt();
            if (len < 0)
            {
                throw new ApkFormatException("Negative length");
            }
            else if (len > buf.remaining())
            {
                throw new ApkFormatException(
                    "Underflow while reading length-prefixed value. Length: " + len
                                                                              + ", available: " + buf.remaining());
            }

            byte[] result = new byte[len];
            buf.get(result);
            return result;
        }

        public static byte[] encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
            List<Tuple<int, byte[]>> sequence)
        {
            int resultSize = 0;
            foreach (Tuple<int, byte[]> element in sequence)
            {
                resultSize += 12 + element.Item2.Length;
            }

            ByteBuffer result = ByteBuffer.allocate(resultSize);
            result.order(ByteOrder.LITTLE_ENDIAN);
            foreach (Tuple<int, byte[]> element in sequence)
            {
                byte[] second = element.Item2;
                result.putInt(8 + second.Length);
                result.putInt(element.Item1);
                result.putInt(second.Length);
                result.put(second);
            }

            return result.array();
        }
    }
}