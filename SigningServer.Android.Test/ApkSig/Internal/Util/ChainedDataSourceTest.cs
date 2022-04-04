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
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Internal.Util
{
    /** Unit tests for {@link ChainedDataSource}. */
    public class ChainedDataSourceTest
    {
        private ChainedDataSource mChain;

        [TestInitialize]
        public void setUp()
        {
            mChain = new ChainedDataSource(
                DataSources.asDataSource(ByteBuffer.wrap(Encoding.UTF8.GetBytes("12"))),
                DataSources.asDataSource(ByteBuffer.wrap(Encoding.UTF8.GetBytes("34567"))),
                DataSources.asDataSource(ByteBuffer.wrap(Encoding.UTF8.GetBytes(""))),
                DataSources.asDataSource(ByteBuffer.wrap(Encoding.UTF8.GetBytes("890"))),
                DataSources.asDataSource(ByteBuffer.wrap(Encoding.UTF8.GetBytes(""))));
            assertEquals(10, mChain.size());
        }

        [TestMethod]
        public void feedAllPossibleRanges()
        {
            for (int begin = 0;
                 begin < mChain.size();
                 begin++)
            {
                for (int end = begin + 1; end < mChain.size(); end++)
                {
                    int size = end - begin;
                    ReadableDataSink sink = DataSinks.newInMemoryDataSink(size);
                    mChain.feed(begin, size, sink);
                    assertByteBufferEquals(
                        ByteBuffer.wrap(Encoding.UTF8.GetBytes("1234567890".Substring(begin, end))),
                    sink.getByteBuffer(0, size));
                }
            }
        }

        [TestMethod]
        [ExpectedException(typeof(IndexOutOfRangeException))]
        public void feedMoreThanAvailable()
        {
            mChain.feed(0, mChain.size() + 1, DataSinks.newInMemoryDataSink(3));
        }

        [TestMethod]
        public void getByteBufferFromAllPossibleRanges()
        {
            for (int begin = 0;
                 begin < mChain.size();
                 begin++)
            {
                for (int end = begin + 1; end < mChain.size(); end++)
                {
                    int size = end - begin;
                    ByteBuffer buffer = mChain.getByteBuffer(begin, size);
                    assertByteBufferEquals(
                        ByteBuffer.wrap(Encoding.UTF8.GetBytes("1234567890".Substring(begin, end))),
                    buffer);
                }
            }
        }

        [TestMethod]
        [ExpectedException(typeof(IndexOutOfRangeException))]
        public void getByteBufferForMoreThanAvailable()

        {
            mChain.getByteBuffer(0, (int)mChain.size() + 1);
        }

        [TestMethod]
        public void copyTo()
        {
            for (int begin = 0;
                 begin < mChain.size();
                 begin++)
            {
                for (int end = begin + 1; end < mChain.size(); end++)
                {
                    int size = end - begin;
                    ByteBuffer buffer = ByteBuffer.allocate(size);
                    mChain.copyTo(begin, size, buffer);
                    assertEquals(size, buffer.position());

                    buffer.rewind();
                    assertByteBufferEquals(
                        ByteBuffer.wrap(Encoding.UTF8.GetBytes("1234567890".Substring(begin, end))),
                    buffer);
                }
            }
        }

        [TestMethod]
        public void slice()

        {
            for (int begin = 0;
                 begin < mChain.size();
                 begin++)
            {
                for (int end = begin + 1; end < mChain.size(); end++)
                {
                    int size = end - begin;
                    ByteBuffer buffer = mChain.slice(begin, size).getByteBuffer(0, size);

                    assertByteBufferEquals(
                        ByteBuffer.wrap(Encoding.UTF8.GetBytes("1234567890".Substring(begin, end))),
                    buffer);
                }
            }
        }

    }
}