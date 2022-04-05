/*
 * Copyright (C) 2018 The Android Open Source Project
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
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Policy;
using System.Threading;
using SigningServer.Android;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.ApkSig.Internal.Pkcs7;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Internal.X509;
using SigningServer.Android.ApkSig.Internal.Zip;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;

namespace SigningServer.Android.ApkSig.Internal.Apk
{
    public class ApkSigningBlockUtils
    {
        private static readonly long CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES = 1024 * 1024;
        public static readonly int ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096;

        private static readonly byte[] APK_SIGNING_BLOCK_MAGIC =
            new byte[]
            {
                0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
                0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32,
            };

        public static readonly int VERITY_PADDING_BLOCK_ID = 0x42726577;

        private static readonly ContentDigestAlgorithm[] V4_CONTENT_DIGEST_ALGORITHMS =
        {
            ContentDigestAlgorithm.CHUNKED_SHA512,
            ContentDigestAlgorithm.VERITY_CHUNKED_SHA256,
            ContentDigestAlgorithm.CHUNKED_SHA256
        };

        public const int VERSION_SOURCE_STAMP = 0;
        public const int VERSION_JAR_SIGNATURE_SCHEME = 1;
        public const int VERSION_APK_SIGNATURE_SCHEME_V2 = 2;
        public const int VERSION_APK_SIGNATURE_SCHEME_V3 = 3;
        public const int VERSION_APK_SIGNATURE_SCHEME_V4 = 4;

        /**
     * Returns positive number if {@code alg1} is preferred over {@code alg2}, {@code -1} if
     * {@code alg2} is preferred over {@code alg1}, and {@code 0} if there is no preference.
     */
        public static int compareSignatureAlgorithm(SignatureAlgorithm alg1, SignatureAlgorithm alg2)
        {
            return ApkSigningBlockUtilsLite.compareSignatureAlgorithm(alg1, alg2);
        }

        /**
     * Verifies integrity of the APK outside of the APK Signing Block by computing digests of the
     * APK and comparing them against the digests listed in APK Signing Block. The expected digests
     * are taken from {@code SignerInfos} of the provided {@code result}.
     *
     * <p>This method adds one or more errors to the {@code result} if a verification error is
     * expected to be encountered on Android. No errors are added to the {@code result} if the APK's
     * integrity is expected to verify on Android for each algorithm in
     * {@code contentDigestAlgorithms}.
     *
     * <p>The reason this method is currently not parameterized by a
     * {@code [minSdkVersion, maxSdkVersion]} range is that up until now content digest algorithms
     * exhibit the same behavior on all Android platform versions.
     */
        public static void verifyIntegrity(
            RunnablesExecutor executor,
            DataSource beforeApkSigningBlock,
            DataSource centralDir,
            ByteBuffer eocd,
            ISet<ContentDigestAlgorithm> contentDigestAlgorithms,
            Result result)
        {
            if (contentDigestAlgorithms.Count == 0)
            {
                // This should never occur because this method is invoked once at least one signature
                // is verified, meaning at least one content digest is known.
                throw new ApplicationException("No content digests found");
            }

            // For the purposes of verifying integrity, ZIP End of Central Directory (EoCD) must be
            // treated as though its Central Directory offset points to the start of APK Signing Block.
            // We thus modify the EoCD accordingly.
            ByteBuffer modifiedEocd = ByteBuffer.allocate(eocd.remaining());
            int eocdSavedPos = eocd.position();
            modifiedEocd.order(ByteOrder.LITTLE_ENDIAN);
            modifiedEocd.put(eocd);
            modifiedEocd.flip();

            // restore eocd to position prior to modification in case it is to be used elsewhere
            eocd.position(eocdSavedPos);
            ZipUtils.setZipEocdCentralDirectoryOffset(modifiedEocd, beforeApkSigningBlock.size());
            Dictionary<ContentDigestAlgorithm, byte[]> actualContentDigests;
            try
            {
                actualContentDigests =
                    computeContentDigests(
                        executor,
                        contentDigestAlgorithms,
                        beforeApkSigningBlock,
                        centralDir,
                        new ByteBufferDataSource(modifiedEocd));
                // Special checks for the verity algorithm requirements.
                if (actualContentDigests.ContainsKey(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256))
                {
                    if ((beforeApkSigningBlock.size() % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0))
                    {
                        throw new ApplicationException(
                            "APK Signing Block is not aligned on 4k boundary: " +
                            beforeApkSigningBlock.size());
                    }

                    long centralDirOffset = ZipUtils.getZipEocdCentralDirectoryOffset(eocd);
                    long signingBlockSize = centralDirOffset - beforeApkSigningBlock.size();
                    if (signingBlockSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0)
                    {
                        throw new ApplicationException(
                            "APK Signing Block size is not multiple of page size: " +
                            signingBlockSize);
                    }
                }
            }
            catch (CryptographicException e)
            {
                throw new ApplicationException("Failed to compute content digests", e);
            }

            if (!contentDigestAlgorithms.SequenceEqual(actualContentDigests.Keys))
            {
                throw new ApplicationException(
                    "Mismatch between sets of requested and computed content digests"
                    + " . Requested: " + contentDigestAlgorithms
                    + ", computed: " + actualContentDigests.Keys);
            }

            // Compare digests computed over the rest of APK against the corresponding expected digests
            // in signer blocks.
            foreach (Result.SignerInfo signerInfo in result.signers)
            {
                foreach (Result.SignerInfo.ContentDigest expected in signerInfo.contentDigests)
                {
                    SignatureAlgorithm signatureAlgorithm =
                        SignatureAlgorithm.findById(expected.getSignatureAlgorithmId());
                    if (signatureAlgorithm == null)
                    {
                        continue;
                    }

                    ContentDigestAlgorithm contentDigestAlgorithm =
                        signatureAlgorithm.getContentDigestAlgorithm();
                    // if the current digest algorithm is not in the list provided by the caller then
                    // ignore it; the signer may contain digests not recognized by the specified SDK
                    // range.
                    if (!contentDigestAlgorithms.Contains(contentDigestAlgorithm))
                    {
                        continue;
                    }

                    byte[] expectedDigest = expected.getValue();
                    byte[] actualDigest = actualContentDigests[contentDigestAlgorithm];
                    if (!expectedDigest.SequenceEqual(actualDigest))
                    {
                        if (result.signatureSchemeVersion == VERSION_APK_SIGNATURE_SCHEME_V2)
                        {
                            signerInfo.addError(
                                (int)ApkVerifier.Issue.V2_SIG_APK_DIGEST_DID_NOT_VERIFY,
                                contentDigestAlgorithm,
                                toHex(expectedDigest),
                                toHex(actualDigest));
                        }
                        else if (result.signatureSchemeVersion == VERSION_APK_SIGNATURE_SCHEME_V3)
                        {
                            signerInfo.addError(
                                (int)ApkVerifier.Issue.V3_SIG_APK_DIGEST_DID_NOT_VERIFY,
                                contentDigestAlgorithm,
                                toHex(expectedDigest),
                                toHex(actualDigest));
                        }

                        continue;
                    }

                    signerInfo.verifiedContentDigests.Add(contentDigestAlgorithm, actualDigest);
                }
            }
        }

        public static ByteBuffer findApkSignatureSchemeBlock(
            ByteBuffer apkSigningBlock,
            int blockId,
            Result result)
        {
            try
            {
                return ApkSigningBlockUtilsLite.findApkSignatureSchemeBlock(apkSigningBlock, blockId);
            }
            catch (Internal.Apk.SignatureNotFoundException e)
            {
                throw new SignatureNotFoundException(e.Message);
            }
        }

        public static void checkByteOrderLittleEndian(ByteBuffer buffer)
        {
            ApkSigningBlockUtilsLite.checkByteOrderLittleEndian(buffer);
        }

        public static ByteBuffer getLengthPrefixedSlice(ByteBuffer source)
        {
            return ApkSigningBlockUtilsLite.getLengthPrefixedSlice(source);
        }

        public static byte[] readLengthPrefixedByteArray(ByteBuffer buf)
        {
            return ApkSigningBlockUtilsLite.readLengthPrefixedByteArray(buf);
        }

        public static String toHex(byte[] value)
        {
            return ApkSigningBlockUtilsLite.toHex(value);
        }

        public static Dictionary<ContentDigestAlgorithm, byte[]> computeContentDigests(
            RunnablesExecutor executor,
            ISet<ContentDigestAlgorithm> digestAlgorithms,
            DataSource beforeCentralDir,
            DataSource centralDir,
            DataSource eocd)

        {
            Dictionary<ContentDigestAlgorithm, byte[]>
                contentDigests = new Dictionary<ContentDigestAlgorithm, byte[]>();
            ISet<ContentDigestAlgorithm> oneMbChunkBasedAlgorithm = new HashSet<ContentDigestAlgorithm>();
            foreach (ContentDigestAlgorithm digestAlgorithm in digestAlgorithms)
            {
                if (digestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA256
                    || digestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA512)
                {
                    oneMbChunkBasedAlgorithm.Add(digestAlgorithm);
                }
            }

            computeOneMbChunkContentDigests(
                executor,
                oneMbChunkBasedAlgorithm,
                new DataSource[] { beforeCentralDir, centralDir, eocd },
                contentDigests);

            if (digestAlgorithms.Contains(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256))
            {
                computeApkVerityDigest(beforeCentralDir, centralDir, eocd, contentDigests);
            }

            return contentDigests;
        }

        public static void computeOneMbChunkContentDigests(
            ISet<ContentDigestAlgorithm> digestAlgorithms,
            DataSource[] contents,
            Dictionary<ContentDigestAlgorithm, byte[]> outputContentDigests)

        {
            // For each digest algorithm the result is computed as follows:
            // 1. Each segment of contents is split into consecutive chunks of 1 MB in size.
            //    The readonly chunk will be shorter iff the length of segment is not a multiple of 1 MB.
            //    No chunks are produced for empty (zero length) segments.
            // 2. The digest of each chunk is computed over the concatenation of byte 0xa5, the chunk's
            //    length in bytes (uint32 little-endian) and the chunk's contents.
            // 3. The output digest is computed over the concatenation of the byte 0x5a, the number of
            //    chunks (uint32 little-endian) and the concatenation of digests of chunks of all
            //    segments in-order.

            long chunkCountLong = 0;
            foreach (DataSource input in contents)
            {
                chunkCountLong +=
                    getChunkCount(input.size(), CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES);
            }

            if (chunkCountLong > int.MaxValue)
            {
                throw new CryptographicException("Input too long: " + chunkCountLong + " chunks");
            }

            int chunkCount = (int)chunkCountLong;

            ContentDigestAlgorithm[] digestAlgorithmsArray = digestAlgorithms.ToArray();
            HashAlgorithm[] mds = new HashAlgorithm[digestAlgorithmsArray.Length];
            byte[][] digestsOfChunks = new byte[digestAlgorithmsArray.Length][];
            int[] digestOutputSizes = new int[digestAlgorithmsArray.Length];
            for (int i = 0; i < digestAlgorithmsArray.Length; i++)
            {
                ContentDigestAlgorithm digestAlgorithm = digestAlgorithmsArray[i];
                int digestOutputSizeBytes = digestAlgorithm.getChunkDigestOutputSizeBytes();
                digestOutputSizes[i] = digestOutputSizeBytes;
                byte[] concatenationOfChunkCountAndChunkDigests =
                    new byte[5 + chunkCount * digestOutputSizeBytes];
                concatenationOfChunkCountAndChunkDigests[0] = 0x5a;
                setUnsignedInt32LittleEndian(
                    chunkCount, concatenationOfChunkCountAndChunkDigests, 1);
                digestsOfChunks[i] = concatenationOfChunkCountAndChunkDigests;
                String jcaAlgorithm = digestAlgorithm.getJcaHashAlgorithmAlgorithm();
                mds[i] = HashAlgorithm.Create(jcaAlgorithm);
            }

            DataSink mdSink = DataSinks.asDataSink(mds);
            byte[] chunkContentPrefix = new byte[5];
            chunkContentPrefix[0] = (byte)0xa5;
            int chunkIndex = 0;
            // Optimization opportunity: digests of chunks can be computed in parallel. However,
            // determining the number of computations to be performed in parallel is non-trivial. This
            // depends on a wide range of factors, such as data source type (e.g., in-memory or fetched
            // from file), CPU/memory/disk cache bandwidth and latency, interconnect architecture of CPU
            // cores, load on the system from other threads of execution and other processes, size of
            // input.
            // For now, we compute these digests sequentially and thus have the luxury of improving
            // performance by writing the digest of each chunk into a pre-allocated buffer at exactly
            // the right position. This avoids unnecessary allocations, copying, and enables the readonly
            // digest to be more efficient because it's presented with all of its input in one go.
            foreach (DataSource input in contents)
            {
                long inputOffset = 0;
                long inputRemaining = input.size();
                while (inputRemaining > 0)
                {
                    int chunkSize =
                        (int)Math.Min(inputRemaining, CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES);
                    setUnsignedInt32LittleEndian(chunkSize, chunkContentPrefix, 1);
                    for (int i = 0; i < mds.Length; i++)
                    {
                        mds[i].TransformBlock(chunkContentPrefix, 0, chunkContentPrefix.Length, null, 0);
                    }

                    try
                    {
                        input.feed(inputOffset, chunkSize, mdSink);
                    }
                    catch (IOException e)
                    {
                        throw new IOException("Failed to read chunk #" + chunkIndex, e);
                    }

                    for (int i = 0; i < digestAlgorithmsArray.Length; i++)
                    {
                        HashAlgorithm md = mds[i];
                        byte[] concatenationOfChunkCountAndChunkDigests = digestsOfChunks[i];
                        int expectedDigestSizeBytes = digestOutputSizes[i];
                        md.TransformFinalBlock(
                            concatenationOfChunkCountAndChunkDigests,
                            5 + chunkIndex * expectedDigestSizeBytes,
                            expectedDigestSizeBytes);
                        md.Initialize();
                        int actualDigestSizeBytes = md.HashSize / 8;
                        if (actualDigestSizeBytes != expectedDigestSizeBytes)
                        {
                            throw new ApplicationException(
                                "Unexpected output size of " + md
                                                             + " digest: " + actualDigestSizeBytes);
                        }
                    }

                    inputOffset += chunkSize;
                    inputRemaining -= chunkSize;
                    chunkIndex++;
                }
            }

            for (int i = 0; i < digestAlgorithmsArray.Length; i++)
            {
                ContentDigestAlgorithm digestAlgorithm = digestAlgorithmsArray[i];
                byte[] concatenationOfChunkCountAndChunkDigests = digestsOfChunks[i];
                HashAlgorithm md = mds[i];
                md.TransformFinalBlock(concatenationOfChunkCountAndChunkDigests, 0,
                    concatenationOfChunkCountAndChunkDigests.Length);
                byte[] digest = md.Hash;
                md.Dispose();
                outputContentDigests.Add(digestAlgorithm, digest);
            }
        }

        public static void computeOneMbChunkContentDigests(
            RunnablesExecutor executor,
            ISet<ContentDigestAlgorithm> digestAlgorithms,
            DataSource[] contents,
            Dictionary<ContentDigestAlgorithm, byte[]> outputContentDigests)

        {
            long chunkCountLong = 0;
            foreach (DataSource input in contents)
            {
                chunkCountLong +=
                    getChunkCount(input.size(), CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES);
            }

            if (chunkCountLong > int.MaxValue)
            {
                throw new CryptographicException("Input too long: " + chunkCountLong + " chunks");
            }

            int chunkCount = (int)chunkCountLong;

            List<ChunkDigests> chunkDigestsList = new List<ChunkDigests>(digestAlgorithms.Count);
            foreach (ContentDigestAlgorithm algorithms in digestAlgorithms)
            {
                chunkDigestsList.Add(new ChunkDigests(algorithms, chunkCount));
            }

            ChunkSupplier chunkSupplier = new ChunkSupplier(contents);
            executor.execute(() => new ChunkDigester(chunkSupplier, chunkDigestsList).run);

            // Compute and write out readonly digest for each algorithm.
            foreach (ChunkDigests chunkDigests in chunkDigestsList)
            {
                HashAlgorithm HashAlgorithm = chunkDigests.createHashAlgorithm();
                outputContentDigests.Add(
                    chunkDigests.algorithm,
                    HashAlgorithm.ComputeHash(chunkDigests.concatOfDigestsOfChunks, 0,
                        chunkDigests.concatOfDigestsOfChunks.Length));
            }
        }

        private class ChunkDigests
        {
            public readonly ContentDigestAlgorithm algorithm;
            public readonly int digestOutputSize;
            public readonly byte[] concatOfDigestsOfChunks;

            public ChunkDigests(ContentDigestAlgorithm algorithm, int chunkCount)
            {
                this.algorithm = algorithm;
                digestOutputSize = this.algorithm.getChunkDigestOutputSizeBytes();
                concatOfDigestsOfChunks = new byte[1 + 4 + chunkCount * digestOutputSize];

                // Fill the initial values of the concatenated digests of chunks, which is
                // {0x5a, 4-bytes-of-little-endian-chunk-count, digests*...}.
                concatOfDigestsOfChunks[0] = 0x5a;
                setUnsignedInt32LittleEndian(chunkCount, concatOfDigestsOfChunks, 1);
            }

            public HashAlgorithm createHashAlgorithm()
            {
                return HashAlgorithm.Create(algorithm.getJcaHashAlgorithmAlgorithm());
            }

            public int getOffset(int chunkIndex)
            {
                return 1 + 4 + chunkIndex * digestOutputSize;
            }
        }

        /**
     * A per-thread digest worker.
     */
        private class ChunkDigester
        {
            private readonly ChunkSupplier dataSupplier;

            private readonly
                List<ChunkDigests> chunkDigests;

            private readonly List<HashAlgorithm> HashAlgorithms;

            private
                readonly DataSink mdSink;

            public ChunkDigester(ChunkSupplier dataSupplier, List<ChunkDigests>
                chunkDigests)
            {
                this.dataSupplier = dataSupplier;
                this.chunkDigests = chunkDigests;
                HashAlgorithms = new List<HashAlgorithm>(chunkDigests.Count);
                foreach (ChunkDigests chunkDigest in chunkDigests)
                {
                    HashAlgorithms.Add(chunkDigest.createHashAlgorithm());
                }

                mdSink = DataSinks.asDataSink(HashAlgorithms.ToArray());
            }


            public void run()
            {
                byte[] chunkContentPrefix = new byte[5];
                chunkContentPrefix[0] = (byte)0xa5;

                try
                {
                    for (ChunkSupplier.Chunk chunk = dataSupplier.get();
                         chunk != null;
                         chunk = dataSupplier.get())
                    {
                        int size = chunk.size;
                        if (size > CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES)
                        {
                            throw new ApplicationException("Chunk size greater than expected: " + size);
                        }

                        // First update with the chunk prefix.
                        setUnsignedInt32LittleEndian(size, chunkContentPrefix, 1);
                        mdSink.consume(chunkContentPrefix, 0, chunkContentPrefix.Length);

                        // Then update with the chunk data.
                        mdSink.consume(chunk.data);

                        // Now readonlyize chunk for all algorithms.
                        for (int i = 0; i < chunkDigests.Count; i++)
                        {
                            ChunkDigests chunkDigest = chunkDigests[i];
                            HashAlgorithms[i].TransformFinalBlock(
                                chunkDigest.concatOfDigestsOfChunks,
                                chunkDigest.getOffset(chunk.chunkIndex),
                                chunkDigest.digestOutputSize);
                            int actualDigestSize = HashAlgorithms[i].HashSize / 8;
                            if (actualDigestSize != chunkDigest.digestOutputSize)
                            {
                                throw new ApplicationException(
                                    "Unexpected output size of " + chunkDigest.algorithm
                                                                 + " digest: " + actualDigestSize);
                            }
                        }
                    }
                }
                catch (Exception e) when (e is IOException || e is CryptographicException)
                {
                    throw new ApplicationException(e.Message, e);
                }
            }
        }

        /**
     * Thread-safe 1MB DataSource chunk supplier. When bounds are met in a
     * supplied {@link DataSource}, the data from the next {@link DataSource}
     * are NOT concatenated. Only the next call to get() will fetch from the
     * next {@link DataSource} in the input {@link DataSource} array.
     */
        private class ChunkSupplier
        {
            private readonly DataSource[] dataSources;
            private readonly int[] chunkCounts;
            private readonly int totalChunkCount;
            private int nextIndex;

            public ChunkSupplier(DataSource[] dataSources)
            {
                this.dataSources = dataSources;
                chunkCounts = new int[dataSources.Length];
                int totalChunkCount = 0;
                for (int i = 0; i < dataSources.Length; i++)
                {
                    long chunkCount = getChunkCount(dataSources[i].size(),
                        CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES);
                    if (chunkCount > int.MaxValue)
                    {
                        throw new ApplicationException(
                            String.Format(
                                "Number of chunks in dataSource[%d] is greater than max int.",
                                i));
                    }

                    chunkCounts[i] = (int)chunkCount;
                    totalChunkCount = (int)(totalChunkCount + chunkCount);
                }

                this.totalChunkCount = totalChunkCount;
                nextIndex = 0;
            }

            /**
         * We map an integer index to the termination-adjusted dataSources 1MB chunks.
         * Note that {@link Chunk}s could be less than 1MB, namely the last 1MB-aligned
         * blocks in each input {@link DataSource} (unless the DataSource itself is
         * 1MB-aligned).
         */
            public ChunkSupplier.Chunk get()
            {
                int index = Interlocked.Increment(ref nextIndex) - 1;
                if (index < 0 || index >= totalChunkCount)
                {
                    return null;
                }

                int dataSourceIndex = 0;
                long dataSourceChunkOffset = index;
                for (; dataSourceIndex < dataSources.Length; dataSourceIndex++)
                {
                    if (dataSourceChunkOffset < chunkCounts[dataSourceIndex])
                    {
                        break;
                    }

                    dataSourceChunkOffset -= chunkCounts[dataSourceIndex];
                }

                long remainingSize = Math.Min(
                    dataSources[dataSourceIndex].size() -
                    dataSourceChunkOffset * CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES,
                    CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES);

                int size = (int)remainingSize;
                ByteBuffer buffer = ByteBuffer.allocate(size);
                try
                {
                    dataSources[dataSourceIndex].copyTo(
                        dataSourceChunkOffset * CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES, size,
                        buffer);
                }
                catch (IOException e)
                {
                    throw new InvalidOperationException("Failed to read chunk", e);
                }

                buffer.rewind();

                return new Chunk(index, buffer, size);
            }

            public class Chunk
            {
                public readonly int chunkIndex;
                public readonly ByteBuffer data;
                public readonly int size;

                public Chunk(int chunkIndex, ByteBuffer data, int size)
                {
                    this.chunkIndex = chunkIndex;
                    this.data = data;
                    this.size = size;
                }
            }
        }

        private static void computeApkVerityDigest(DataSource beforeCentralDir, DataSource centralDir,
            DataSource eocd, Dictionary<ContentDigestAlgorithm, byte[]> outputContentDigests)

        {
            ByteBuffer encoded = createVerityDigestBuffer(true);
            // Use 0s as salt for now.  This also needs to be consistent in the fsverify header for
            // kernel to use.
            using (VerityTreeBuilder builder = new VerityTreeBuilder(new byte[8]))
            {
                byte[] rootHash = builder.generateVerityTreeRootHash(beforeCentralDir, centralDir,
                    eocd);
                encoded.put(rootHash);
                encoded.putLong(beforeCentralDir.size() + centralDir.size() + eocd.size());
                outputContentDigests.Add(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, encoded.array());
            }
        }

        private static ByteBuffer createVerityDigestBuffer(bool includeSourceDataSize)
        {
            // FORMAT:
            // OFFSET       DATA TYPE  DESCRIPTION
            // * @+0  bytes uint8[32]  Merkle tree root hash of SHA-256
            // * @+32 bytes int64      (optional) Length of source data
            int backBufferSize =
                ContentDigestAlgorithm.VERITY_CHUNKED_SHA256.getChunkDigestOutputSizeBytes();
            if (includeSourceDataSize)
            {
                backBufferSize += sizeof(long) / sizeof(byte);
            }

            ByteBuffer encoded = ByteBuffer.allocate(backBufferSize);
            encoded.order(ByteOrder.LITTLE_ENDIAN);
            return encoded;
        }

        public class VerityTreeAndDigest
        {
            public readonly ContentDigestAlgorithm contentDigestAlgorithm;
            public readonly byte[] rootHash;
            public readonly byte[] tree;

            public VerityTreeAndDigest(ContentDigestAlgorithm contentDigestAlgorithm, byte[] rootHash,
                byte[] tree)
            {
                this.contentDigestAlgorithm = contentDigestAlgorithm;
                this.rootHash = rootHash;
                this.tree = tree;
            }
        }

        public static VerityTreeAndDigest computeChunkVerityTreeAndDigest(DataSource dataSource)
        {
            ByteBuffer encoded = createVerityDigestBuffer(false);
            // Use 0s as salt for now.  This also needs to be consistent in the fsverify header for
            // kernel to use.
            using (VerityTreeBuilder builder = new VerityTreeBuilder(null))
            {
                ByteBuffer tree = builder.generateVerityTree(dataSource);
                byte[] rootHash = builder.getRootHashFromTree(tree);
                encoded.put(rootHash);
                return new VerityTreeAndDigest(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, encoded.array(),
                    tree.array());
            }
        }

        private static long getChunkCount(long inputSize, long chunkSize)
        {
            return (inputSize + chunkSize - 1) / chunkSize;
        }

        private static void setUnsignedInt32LittleEndian(int value, byte[] result, int offset)
        {
            result[offset] = (byte)(value & 0xff);
            result[offset + 1] = (byte)((value >> 8) & 0xff);
            result[offset + 2] = (byte)((value >> 16) & 0xff);
            result[offset + 3] = (byte)((value >> 24) & 0xff);
        }

        public static byte[] encodePublicKey(PublicKey publicKey)
        {
            byte[] encodedPublicKey = publicKey.getEncoded();
            // if the key is an RSA key check for a negative modulus
            if ("RSA".Equals(publicKey.getAlgorithm()))
            {
                try
                {
                    // Parse the encoded public key into the separate elements of the
                    // SubjectPublicKeyInfo to obtain the SubjectPublicKey.
                    ByteBuffer encodedPublicKeyBuffer = ByteBuffer.wrap(encodedPublicKey);
                    SubjectPublicKeyInfo subjectPublicKeyInfo = Asn1BerParser.parse<SubjectPublicKeyInfo>(
                        encodedPublicKeyBuffer);
                    // The SubjectPublicKey is encoded as a bit string within the
                    // SubjectPublicKeyInfo. The first byte of the encoding is the number of padding
                    // bits; store this and decode the rest of the bit string into the RSA modulus
                    // and exponent.
                    ByteBuffer subjectPublicKeyBuffer = subjectPublicKeyInfo.subjectPublicKey;
                    byte padding = subjectPublicKeyBuffer.get();
                    RSAPublicKey rsaPublicKey = Asn1BerParser.parse<RSAPublicKey>(subjectPublicKeyBuffer);
                    // if the modulus is negative then attempt to reencode it with a leading 0 sign
                    // byte.
                    if (rsaPublicKey.modulus.CompareTo(BigInteger.Zero) < 0)
                    {
                        // A negative modulus indicates the leading bit in the integer is 1. Per
                        // ASN.1 encoding rules to encode a positive integer with the leading bit
                        // set to 1 a byte containing all zeros should precede the integer encoding.
                        byte[] encodedModulus = rsaPublicKey.modulus.ToByteArray();
                        byte[] reencodedModulus = new byte[encodedModulus.Length + 1];
                        reencodedModulus[0] = 0;
                        Array.Copy(encodedModulus, 0, reencodedModulus, 1,
                            encodedModulus.Length);
                        rsaPublicKey.modulus = new BigInteger(reencodedModulus);
                        // Once the modulus has been corrected reencode the RSAPublicKey, then
                        // restore the padding value in the bit string and reencode the entire
                        // SubjectPublicKeyInfo to be returned to the caller.
                        byte[] reencodedRSAPublicKey = Asn1DerEncoder.encode(rsaPublicKey);
                        byte[] reencodedSubjectPublicKey =
                            new byte[reencodedRSAPublicKey.Length + 1];
                        reencodedSubjectPublicKey[0] = padding;
                        Array.Copy(reencodedRSAPublicKey, 0, reencodedSubjectPublicKey, 1,
                            reencodedRSAPublicKey.Length);
                        subjectPublicKeyInfo.subjectPublicKey = ByteBuffer.wrap(
                            reencodedSubjectPublicKey);
                        encodedPublicKey = Asn1DerEncoder.encode(subjectPublicKeyInfo);
                    }
                }
                catch (Exception e) when (e is Asn1DecodingException || e is Asn1EncodingException)
                {
                    Console.WriteLine("Caught a exception encoding the public key: " + e);
                    encodedPublicKey = null;
                }
            }

            if (encodedPublicKey == null)
            {
                encodedPublicKey = publicKey.getEncoded();
            }

            return encodedPublicKey;
        }

        public static List<byte[]> encodeCertificates(List<X509Certificate> certificates)
        {
            List<byte[]> result = new List<byte[]>(certificates.Count);
            foreach (var certificate in certificates)
            {
                result.Add(certificate.getEncoded());
            }

            return result;
        }

        public static byte[] encodeAsLengthPrefixedElement(byte[] bytes)
        {
            byte[][] adapterBytes = new byte[1][];
            adapterBytes[0] = bytes;
            return encodeAsSequenceOfLengthPrefixedElements(adapterBytes);
        }

        public static byte[] encodeAsSequenceOfLengthPrefixedElements(List<byte[]> sequence)
        {
            return encodeAsSequenceOfLengthPrefixedElements(
                sequence.ToArray());
        }

        public static byte[] encodeAsSequenceOfLengthPrefixedElements(byte[][] sequence)
        {
            int payloadSize = 0;

            foreach (byte[] element in sequence)
            {
                payloadSize += 4 + element.Length;
            }

            ByteBuffer result = ByteBuffer.allocate(payloadSize);
            result.order(ByteOrder.LITTLE_ENDIAN);
            foreach (byte[] element in sequence)
            {
                result.putInt(element.Length);
                result.put(element);
            }

            return result.array();
        }

        public static byte[] encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
            List<Tuple<int, byte[]>> sequence)
        {
            return ApkSigningBlockUtilsLite
                .encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(sequence);
        }

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
            DataSource apk, ZipSections zipSections, int blockId, Result result)

        {
            try
            {
                return ApkSigningBlockUtilsLite.findSignature(apk, zipSections, blockId);
            }
            catch (Internal.Apk.SignatureNotFoundException e)
            {
                throw new SignatureNotFoundException(e.Message);
            }
        }

        /**
     * Generates a new DataSource representing the APK contents before the Central Directory with
     * padding, if padding is requested.  If the existing data entries before the Central Directory
     * are already aligned, or no padding is requested, the original DataSource is used.  This
     * padding is used to allow for verity-based APK verification.
     *
     * @return {@code Pair} containing the potentially new {@code DataSource} and the amount of
     *         padding used.
     */
        public static Tuple<DataSource, int> generateApkSigningBlockPadding(
            DataSource beforeCentralDir,
            bool apkSigningBlockPaddingSupported)
        {
            // Ensure APK Signing Block starts from page boundary.
            int padSizeBeforeSigningBlock = 0;
            if (apkSigningBlockPaddingSupported &&
                (beforeCentralDir.size() % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0))
            {
                padSizeBeforeSigningBlock = (int)(
                    ANDROID_COMMON_PAGE_ALIGNMENT_BYTES -
                    beforeCentralDir.size() % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES);
                beforeCentralDir = new ChainedDataSource(
                    beforeCentralDir,
                    DataSources.asDataSource(
                        ByteBuffer.allocate(padSizeBeforeSigningBlock)));
            }

            return Tuple.Create(beforeCentralDir, padSizeBeforeSigningBlock);
        }

        public static DataSource copyWithModifiedCDOffset(
            DataSource beforeCentralDir, DataSource eocd)

        {
            // Ensure that, when digesting, ZIP End of Central Directory record's Central Directory
            // offset field is treated as pointing to the offset at which the APK Signing Block will
            // start.
            long centralDirOffsetForDigesting = beforeCentralDir.size();
            ByteBuffer eocdBuf = ByteBuffer.allocate((int)eocd.size());
            eocdBuf.order(ByteOrder.LITTLE_ENDIAN);
            eocd.copyTo(0, (int)eocd.size(), eocdBuf);
            eocdBuf.flip();
            ZipUtils.setZipEocdCentralDirectoryOffset(eocdBuf, centralDirOffsetForDigesting);
            return DataSources.asDataSource(eocdBuf);
        }

        public static byte[] generateApkSigningBlock(
            List<Tuple<byte[], int>> apkSignatureSchemeBlockPairs)
        {
            // FORMAT:
            // uint64:  size (excluding this field)
            // repeated ID-value pairs:
            //     uint64:           size (excluding this field)
            //     uint32:           ID
            //     (size - 4) bytes: value
            // (extra verity ID-value for padding to make block size a multiple of 4096 bytes)
            // uint64:  size (same as the one above)
            // uint128: magic

            int blocksSize = 0;
            foreach (var schemeBlockPair in apkSignatureSchemeBlockPairs)
            {
                blocksSize += 8 + 4 + schemeBlockPair.Item1.Length; // size + id + value
            }

            int resultSize =
                    8 // size
                    + blocksSize
                    + 8 // size
                    + 16 // magic
                ;
            ByteBuffer paddingPair = null;
            if (resultSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0)
            {
                int padding = ANDROID_COMMON_PAGE_ALIGNMENT_BYTES -
                              (resultSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES);
                if (padding < 12)
                {
                    // minimum size of an ID-value pair
                    padding += ANDROID_COMMON_PAGE_ALIGNMENT_BYTES;
                }

                paddingPair = ByteBuffer.allocate(padding).order(ByteOrder.LITTLE_ENDIAN);
                paddingPair.putLong(padding - 8);
                paddingPair.putInt(VERITY_PADDING_BLOCK_ID);
                paddingPair.rewind();
                resultSize += padding;
            }

            ByteBuffer result = ByteBuffer.allocate(resultSize);
            result.order(ByteOrder.LITTLE_ENDIAN);
            long blockSizeFieldValue = resultSize - 8L;
            result.putLong(blockSizeFieldValue);

            foreach (Tuple<byte[], int> schemeBlockPair in apkSignatureSchemeBlockPairs)
            {
                byte[] apkSignatureSchemeBlock = schemeBlockPair.Item1;
                int apkSignatureSchemeId = schemeBlockPair.Item2;
                long pairSizeFieldValue = 4L + apkSignatureSchemeBlock.Length;
                result.putLong(pairSizeFieldValue);
                result.putInt(apkSignatureSchemeId);
                result.put(apkSignatureSchemeBlock);
            }

            if (paddingPair != null)
            {
                result.put(paddingPair);
            }

            result.putLong(blockSizeFieldValue);
            result.put(APK_SIGNING_BLOCK_MAGIC);

            return result.array();
        }

        /**
     * Returns the individual APK signature blocks within the provided {@code apkSigningBlock} in a
     * {@code List} of {@code Pair} instances where the first element in the {@code Pair} is the
     * contents / value of the signature block and the second element is the ID of the block.
     *
     * @throws IOException if an error is encountered reading the provided {@code apkSigningBlock}
     */
        public static List<Tuple<byte[], int>> getApkSignatureBlocks(
            DataSource apkSigningBlock)

        {
            // FORMAT:
            // uint64:  size (excluding this field)
            // repeated ID-value pairs:
            //     uint64:           size (excluding this field)
            //     uint32:           ID
            //     (size - 4) bytes: value
            // (extra verity ID-value for padding to make block size a multiple of 4096 bytes)
            // uint64:  size (same as the one above)
            // uint128: magic
            long apkSigningBlockSize = apkSigningBlock.size();
            if (apkSigningBlock.size() > int.MaxValue || apkSigningBlockSize < 32)
            {
                throw new ArgumentException(
                    "APK signing block size out of range: " + apkSigningBlockSize);
            }

            // Remove the header and footer from the signing block to iterate over only the repeated
            // ID-value pairs.
            ByteBuffer apkSigningBlockBuffer = apkSigningBlock.getByteBuffer(8,
                (int)apkSigningBlock.size() - 32);
            apkSigningBlockBuffer.order(ByteOrder.LITTLE_ENDIAN);
            List<Tuple<byte[], int>> signatureBlocks = new List<Tuple<byte[], int>>();
            while (apkSigningBlockBuffer.hasRemaining())
            {
                long blockLength = apkSigningBlockBuffer.getLong();
                if (blockLength > int.MaxValue || blockLength < 4)
                {
                    throw new ArgumentException(
                        "Block index " + (signatureBlocks.Count + 1) + " size out of range: "
                        + blockLength);
                }

                int blockId = apkSigningBlockBuffer.getInt();
                // Since the block ID has already been read from the signature block read the next
                // blockLength - 4 bytes as the value.
                byte[] blockValue = new byte[(int)blockLength - 4];
                apkSigningBlockBuffer.get(blockValue);
                signatureBlocks.Add(Tuple.Create(blockValue, blockId));
            }

            return signatureBlocks;
        }

        /**
     * Returns the individual APK signers within the provided {@code signatureBlock} in a {@code
     * List} of {@code Pair} instances where the first element is a {@code List} of {@link
     * X509Certificate}s and the second element is a byte array of the individual signer's block.
     *
     * <p>This method supports any signature block that adheres to the following format up to the
     * signing certificate(s):
     * <pre>
     * * length-prefixed sequence of length-prefixed signers
     *   * length-prefixed signed data
     *     * length-prefixed sequence of length-prefixed digests:
     *       * uint32: signature algorithm ID
     *       * length-prefixed bytes: digest of contents
     *     * length-prefixed sequence of certificates:
     *       * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
     * </pre>
     *
     * <p>Note, this is a convenience method to obtain any signers from an existing signature block;
     * the signature of each signer will not be verified.
     *
     * @throws ApkFormatException if an error is encountered while parsing the provided {@code
     * signatureBlock}
     * @throws CertificateException if the signing certificate(s) within an individual signer block
     * cannot be parsed
     */
        public static List<Tuple<List<X509Certificate>, byte[]>> getApkSignatureBlockSigners(
            byte[] signatureBlock)

        {
            ByteBuffer signatureBlockBuffer = ByteBuffer.wrap(signatureBlock);
            signatureBlockBuffer.order(ByteOrder.LITTLE_ENDIAN);
            ByteBuffer signersBuffer = getLengthPrefixedSlice(signatureBlockBuffer);
            List<Tuple<List<X509Certificate>, byte[]>> signers = new List<Tuple<List<X509Certificate>, byte[]>>();
            while (signersBuffer.hasRemaining())
            {
                // Parse the next signer block, save all of its bytes for the resulting List, and
                // rewind the buffer to allow the signing certificate(s) to be parsed.
                ByteBuffer signer = getLengthPrefixedSlice(signersBuffer);
                byte[] signerBytes = new byte[signer.remaining()];
                signer.get(signerBytes);
                signer.rewind();

                ByteBuffer signedData = getLengthPrefixedSlice(signer);
                // The first length prefixed slice is the sequence of digests which are not required
                // when obtaining the signing certificate(s).
                getLengthPrefixedSlice(signedData);
                ByteBuffer certificatesBuffer = getLengthPrefixedSlice(signedData);
                List<X509Certificate> certificates = new List<X509Certificate>();
                while (certificatesBuffer.hasRemaining())
                {
                    int certLength = certificatesBuffer.getInt();
                    byte[] certBytes = new byte[certLength];
                    if (certLength > certificatesBuffer.remaining())
                    {
                        throw new ArgumentException(
                            "Cert index " + (certificates.Count + 1) + " under signer index "
                            + (signers.Count + 1) + " size out of range: " + certLength);
                    }

                    certificatesBuffer.get(certBytes);
                    GuaranteedEncodedFormX509Certificate signerCert =
                        new GuaranteedEncodedFormX509Certificate(
                            X509CertificateUtils.generateCertificate(certBytes), certBytes);
                    certificates.Add(signerCert);
                }

                signers.Add(Tuple.Create(certificates, signerBytes));
            }

            return signers;
        }

        /**
     * Computes the digests of the given APK components according to the algorithms specified in the
     * given SignerConfigs.
     *
     * @param signerConfigs signer configurations, one for each signer At least one signer config
     *        must be provided.
     *
     * @throws IOException if an I/O error occurs
     * @throws NoSuchAlgorithmException if a required cryptographic algorithm implementation is
     *         missing
     * @throws SignatureException if an error occurs when computing digests of generating
     *         signatures
     */
        public static Tuple<List<SignerConfig>, Dictionary<ContentDigestAlgorithm, byte[]>>
            computeContentDigests(
                RunnablesExecutor executor,
                DataSource beforeCentralDir,
                DataSource centralDir,
                DataSource eocd,
                List<SignerConfig> signerConfigs)

        {
            if (signerConfigs.Count == 0)
            {
                throw new ArgumentException(
                    "No signer configs provided. At least one is required");
            }

            // Figure out which digest(s) to use for APK contents.
            ISet<ContentDigestAlgorithm> contentDigestAlgorithms = new HashSet<ContentDigestAlgorithm>(1);
            foreach (SignerConfig signerConfig in signerConfigs)
            {
                foreach (SignatureAlgorithm signatureAlgorithm in signerConfig.signatureAlgorithms)
                {
                    contentDigestAlgorithms.Add(signatureAlgorithm.getContentDigestAlgorithm());
                }
            }

            // Compute digests of APK contents.
            Dictionary<ContentDigestAlgorithm, byte[]> contentDigests; // digest algorithm ID -> digest
            try
            {
                contentDigests =
                    computeContentDigests(
                        executor,
                        contentDigestAlgorithms,
                        beforeCentralDir,
                        centralDir,
                        eocd);
            }
            catch (IOException e)
            {
                throw new IOException("Failed to read APK being signed", e);
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException("Failed to compute digests of APK", e);
            }

            // Sign the digests and wrap the signatures and signer info into an APK Signing Block.
            return Tuple.Create(signerConfigs, contentDigests);
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
     * @throws NoSupportedSignaturesException if no supported signatures were
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
     * @throws NoSupportedSignaturesException if no supported signatures were
     *         found for an Android platform version in the range.
     */
        public static List<T> getSignaturesToVerify<T>(
            List<T> signatures, int minSdkVersion, int maxSdkVersion,
            bool onlyRequireJcaSupport) where T : ApkSupportedSignature
        {
            try
            {
                return ApkSigningBlockUtilsLite.getSignaturesToVerify(signatures, minSdkVersion,
                    maxSdkVersion, onlyRequireJcaSupport);
            }
            catch (NoApkSupportedSignaturesException e)
            {
                throw new NoSupportedSignaturesException(e.Message);
            }
        }

        public class NoSupportedSignaturesException
            : NoApkSupportedSignaturesException
        {
            public NoSupportedSignaturesException(String message) : base(message)
            {
            }
        }

        public class SignatureNotFoundException
            : Exception
        {
            public SignatureNotFoundException(String message) : base(message)
            {
            }

            public SignatureNotFoundException(String message, Exception cause) : base(message, cause)
            {
            }
        }

        /**
     * uses the SignatureAlgorithms in the provided signerConfig to sign the provided data
     *
     * @return list of signature algorithm IDs and their corresponding signatures over the data.
     */
        public static List<Tuple<int, byte[]>> generateSignaturesOverData(
            SignerConfig signerConfig, byte[] data)

        {
            List<Tuple<int, byte[]>> signatures =
                new List<Tuple<int, byte[]>>(signerConfig.signatureAlgorithms.Count);
            PublicKey publicKey = signerConfig.certificates[0].getPublicKey();
            foreach (SignatureAlgorithm signatureAlgorithm in signerConfig.signatureAlgorithms)
            {
                Tuple<String, AlgorithmParameterSpec> sigAlgAndParams =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams();
                String jcaSignatureAlgorithm = sigAlgAndParams.Item1;
                AlgorithmParameterSpec jcaSignatureAlgorithmParams = sigAlgAndParams.Item2;
                byte[] signatureBytes;
                try
                {
                    Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
                    signature.initSign(signerConfig.privateKey);
                    if (jcaSignatureAlgorithmParams != null)
                    {
                        signature.setParameter(jcaSignatureAlgorithmParams);
                    }
                    
                    signature.update(data);
                    signatureBytes = signature.sign();
                }
                catch (CryptographicException e)
                {
                    throw new CryptographicException("Failed to sign using " + jcaSignatureAlgorithm, e);
                }

                try
                {
                    Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
                    signature.initVerify(publicKey);
                    if (jcaSignatureAlgorithmParams != null)
                    {
                        signature.setParameter(jcaSignatureAlgorithmParams);
                    }

                    signature.update(data);
                    if (!signature.verify(signatureBytes))
                    {
                        throw new CryptographicException("Failed to verify generated "
                                                     + jcaSignatureAlgorithm
                                                     + " signature using public key from certificate");
                    }
                }
                catch (CryptographicException e)
                {
                    throw new CryptographicException(
                        "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                        + " public key from certificate", e);
                }

                signatures.Add(Tuple.Create(signatureAlgorithm.getId(), signatureBytes));
            }

            return signatures;
        }

        /**
     * Wrap the signature according to CMS PKCS #7 RFC 5652.
     * The high-level simplified structure is as follows:
     * // ContentInfo
     *     //   digestAlgorithm
     *     //   SignedData
     *     //     bag of certificates
     *     //     SignerInfo
     *     //       signing cert issuer and serial number (for locating the cert in the above bag)
     *     //       digestAlgorithm
     *     //       signatureAlgorithm
     *     //       signature
     *
     * @throws Asn1EncodingException if the ASN.1 structure could not be encoded
     */
        public static byte[] generatePkcs7DerEncodedMessage(
            byte[] signatureBytes, ByteBuffer data, List<X509Certificate> signerCerts,
            AlgorithmIdentifier digestAlgorithmId, AlgorithmIdentifier signatureAlgorithmId)

        {
            SignerInfo signerInfo = new SignerInfo();
            signerInfo.version = 1;
            X509Certificate signingCert = signerCerts[0];
            var signerCertIssuer = signingCert.getIssuerX500Principal();
            signerInfo.sid =
                new SignerIdentifier(
                    new IssuerAndSerialNumber(
                        new Asn1OpaqueObject(signerCertIssuer.getEncoded()),
                        signingCert.getSerialNumber()));

            signerInfo.digestAlgorithm = digestAlgorithmId;
            signerInfo.signatureAlgorithm = signatureAlgorithmId;
            signerInfo.signature = ByteBuffer.wrap(signatureBytes);

            SignedData signedData = new SignedData();
            signedData.certificates = new List<Asn1OpaqueObject>(signerCerts.Count);
            foreach (X509Certificate cert in signerCerts)
            {
                signedData.certificates.Add(new Asn1OpaqueObject(cert.getEncoded()));
            }

            signedData.version = 1;
            signedData.digestAlgorithms = new List<AlgorithmIdentifier>
            {
                digestAlgorithmId
            };
            signedData.encapContentInfo = new EncapsulatedContentInfo(Pkcs7Constants.OID_DATA);
            // If data is not null, data will be embedded as is in the result -- an attached pcsk7
            signedData.encapContentInfo.content = data;
            signedData.signerInfos = new List<SignerInfo>
            {
                signerInfo
            };
            ContentInfo contentInfo = new ContentInfo();
            contentInfo.contentType = Pkcs7Constants.OID_SIGNED_DATA;
            contentInfo.content = new Asn1OpaqueObject(Asn1DerEncoder.encode(signedData));
            return Asn1DerEncoder.encode(contentInfo);
        }

        /**
     * Picks the correct v2/v3 digest for v4 signature verification.
     *
     * Keep in sync with pickBestDigestForV4 in framework's ApkSigningBlockUtils.
     */
        public static byte[] pickBestDigestForV4(Dictionary<ContentDigestAlgorithm, byte[]> contentDigests)
        {
            foreach (ContentDigestAlgorithm algo in V4_CONTENT_DIGEST_ALGORITHMS)
            {
                if (contentDigests.ContainsKey(algo))
                {
                    return contentDigests[algo];
                }
            }

            return null;
        }

        /**
     * Signer configuration.
     */
        public class SignerConfig
        {
            /** Private key. */
            public PrivateKey privateKey;

            /**
         * Certificates, with the first certificate containing the public key corresponding to
         * {@link #privateKey}.
         */
            public List<X509Certificate> certificates;

            /**
         * List of signature algorithms with which to sign.
         */
            public List<SignatureAlgorithm> signatureAlgorithms;

            public int minSdkVersion;
            public int maxSdkVersion;
            public SigningCertificateLineage mSigningCertificateLineage;
        }

        public class Result : ApkSigResult
        {
            public SigningCertificateLineage signingCertificateLineage = null;
            public readonly List<Result.SignerInfo> signers = new List<Result.SignerInfo>();
            private readonly List<ApkVerificationIssue> mWarnings = new List<ApkVerificationIssue>();
            private readonly List<ApkVerificationIssue> mErrors = new List<ApkVerificationIssue>();

            public Result(int signatureSchemeVersion) : base(signatureSchemeVersion)
            {
            }

            public override bool containsErrors()
            {
                if (mErrors.Count != 0)
                {
                    return true;
                }

                if (signers.Count != 0)
                {
                    foreach (Result.SignerInfo signer in signers)
                    {
                        if (signer.containsErrors())
                        {
                            return true;
                        }
                    }
                }

                return false;
            }

            public override bool containsWarnings()
            {
                if (mWarnings.Count != 0)
                {
                    return true;
                }

                if (signers.Count != 0)
                {
                    foreach (Result.SignerInfo signer in signers)
                    {
                        if (signer.containsWarnings())
                        {
                            return true;
                        }
                    }
                }

                return false;
            }

            public void addError(ApkVerifier.Issue msg, params Object[] parameters)
            {
                mErrors.Add(new ApkVerifier.IssueWithParams(msg, parameters));
            }

            public void addWarning(ApkVerifier.Issue msg, params Object[] parameters)
            {
                mWarnings.Add(new ApkVerifier.IssueWithParams(msg, parameters));
            }


            public override List<ApkVerificationIssue> getErrors()
            {
                return mErrors;
            }


            public override List<ApkVerificationIssue> getWarnings()
            {
                return mWarnings;
            }

            public class SignerInfo
                : ApkSignerInfo
            {
                public List<ContentDigest> contentDigests = new List<ContentDigest>();

                public Dictionary<ContentDigestAlgorithm, byte[]> verifiedContentDigests =
                    new Dictionary<ContentDigestAlgorithm, byte[]>();

                public List<Signature> signatures = new List<Signature>();

                public Dictionary<SignatureAlgorithm, byte[]> verifiedSignatures =
                    new Dictionary<SignatureAlgorithm, byte[]>();

                public List<AdditionalAttribute> additionalAttributes = new List<AdditionalAttribute>();
                public byte[] signedData;
                public int minSdkVersion;
                public int maxSdkVersion;
                public SigningCertificateLineage signingCertificateLineage;
                private readonly List<ApkVerificationIssue> mWarnings = new List<ApkVerificationIssue>();
                private readonly List<ApkVerificationIssue> mErrors = new List<ApkVerificationIssue>();

                public void addError(ApkVerifier.Issue msg, params Object[] parameters)
                {
                    mErrors.Add(new ApkVerifier.IssueWithParams(msg, parameters));
                }

                public void addWarning(ApkVerifier.Issue msg, params Object[] parameters)
                {
                    mWarnings.Add(new ApkVerifier.IssueWithParams(msg, parameters));
                }

                public override bool containsErrors()
                {
                    return mErrors.Count != 0;
                }

                public override bool containsWarnings()
                {
                    return mWarnings.Count != 0;
                }

                public override List<ApkVerificationIssue> getErrors()
                {
                    return mErrors;
                }

                public override List<ApkVerificationIssue> getWarnings()
                {
                    return mWarnings;
                }

                public class ContentDigest
                {
                    private readonly int mSignatureAlgorithmId;
                    private readonly byte[] mValue;

                    public ContentDigest(int signatureAlgorithmId, byte[] value)
                    {
                        mSignatureAlgorithmId = signatureAlgorithmId;
                        mValue = value;
                    }

                    public int getSignatureAlgorithmId()
                    {
                        return mSignatureAlgorithmId;
                    }

                    public byte[] getValue()
                    {
                        return mValue;
                    }
                }

                public class Signature
                {
                    private readonly int mAlgorithmId;
                    private readonly byte[] mValue;

                    public Signature(int algorithmId, byte[] value)
                    {
                        mAlgorithmId = algorithmId;
                        mValue = value;
                    }

                    public int getAlgorithmId()
                    {
                        return mAlgorithmId;
                    }

                    public byte[] getValue()
                    {
                        return mValue;
                    }
                }

                public class AdditionalAttribute
                {
                    private readonly int mId;
                    private readonly byte[] mValue;

                    public AdditionalAttribute(int id, byte[] value)
                    {
                        mId = id;
                        mValue = (byte[])value.Clone();
                    }

                    public int getId()
                    {
                        return mId;
                    }

                    public byte[] getValue()
                    {
                        return (byte[])mValue.Clone();
                    }
                }
            }
        }

        public class SupportedSignature
            : ApkSupportedSignature
        {
            public SupportedSignature(SignatureAlgorithm algorithm, byte[] signature)
                : base(algorithm, signature)
            {
            }
        }

        public class SigningSchemeBlockAndDigests
        {
            public readonly Tuple<byte[], int> signingSchemeBlock;
            public readonly Dictionary<ContentDigestAlgorithm, byte[]> digestInfo;

            public SigningSchemeBlockAndDigests(
                Tuple<byte[], int> signingSchemeBlock,
                Dictionary<ContentDigestAlgorithm, byte[]> digestInfo)
            {
                this.signingSchemeBlock = signingSchemeBlock;
                this.digestInfo = digestInfo;
            }
        }
    }
}