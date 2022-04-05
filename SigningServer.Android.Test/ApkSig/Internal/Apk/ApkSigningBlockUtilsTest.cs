/*
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
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Internal.Apk
{
    [TestClass]
    public class ApkSigningBlockUtilsTest
    {
        private static readonly int BASE = 255; // Intentionally not power of 2 to test properly

        DataSource[] dataSource;

        private ISet<ContentDigestAlgorithm> algos = new HashSet<ContentDigestAlgorithm>
        {
            ContentDigestAlgorithm.CHUNKED_SHA512
        };

        [TestInitialize]
        public void setUp()
        {
            byte[] part1 = new byte[80 * 1024 * 1024 + 12345];
            for (int i = 0; i < part1.Length; ++i)
            {
                part1[i] = (byte)(i % BASE);
            }

            FileInfo dataFile = new FileInfo(Path.GetTempFileName());
            File.WriteAllBytes(dataFile.FullName, part1);

            RandomAccessFile raf = new RandomAccessFile(dataFile, "r");

            byte[] part2 = new byte[1_500_000];
            for (int i = 0; i < part2.Length; ++i)
            {
                part2[i] = (byte)(i % BASE);
            }

            byte[] part3 = new byte[30_000];
            for (int i = 0; i < part3.Length; ++i)
            {
                part3[i] = (byte)(i % BASE);
            }

            dataSource = new DataSource[]
            {
                DataSources.asDataSource(raf),
                DataSources.asDataSource(ByteBuffer.wrap(part2)),
                DataSources.asDataSource(ByteBuffer.wrap(part3)),
            };
        }

        [TestMethod]
        public void testNewVersionMatchesOld()
        {
            Dictionary<ContentDigestAlgorithm, byte[]> outputContentDigestsOld =
                new Dictionary<ContentDigestAlgorithm, byte[]>();

            Dictionary<ContentDigestAlgorithm, byte[]> outputContentDigestsNew =
                new Dictionary<ContentDigestAlgorithm, byte[]>();

            ApkSigningBlockUtils.computeOneMbChunkContentDigests(
                algos, dataSource, outputContentDigestsOld);

            ApkSigningBlockUtils.computeOneMbChunkContentDigests(
                RunnablesExecutors.SINGLE_THREADED,
                algos, dataSource, outputContentDigestsNew);

            assertEqualDigests(outputContentDigestsOld, outputContentDigestsNew);
        }

        [TestMethod]
        public void testMultithreadedVersionMatchesSinglethreaded()
        {
            Dictionary<ContentDigestAlgorithm, byte[]> outputContentDigests =
                new Dictionary<ContentDigestAlgorithm, byte[]>();
            Dictionary<ContentDigestAlgorithm, byte[]> outputContentDigestsMultithreaded =
                new Dictionary<ContentDigestAlgorithm, byte[]>();

            ApkSigningBlockUtils.computeOneMbChunkContentDigests(
                RunnablesExecutors.SINGLE_THREADED,
                algos, dataSource, outputContentDigests);

            ApkSigningBlockUtils.computeOneMbChunkContentDigests(
                RunnablesExecutors.MULTI_THREADED,
                algos, dataSource, outputContentDigestsMultithreaded);

            assertEqualDigests(outputContentDigestsMultithreaded, outputContentDigests);
        }

        private void assertEqualDigests(
            Dictionary<ContentDigestAlgorithm, byte[]> d1, Dictionary<ContentDigestAlgorithm, byte[]> d2)
        {
            assertEquals((IEnumerable<ContentDigestAlgorithm>)d1.Keys, d2.Keys);
            foreach (ContentDigestAlgorithm algo in d1.Keys)
            {
                byte[] digest1 = d1[algo];
                byte[] digest2 = d2[algo];
                assertArrayEquals(digest1, digest2);
            }
        }
    }
}