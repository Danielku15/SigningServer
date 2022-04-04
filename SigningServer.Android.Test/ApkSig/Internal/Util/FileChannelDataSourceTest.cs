/*
 * Copyright (C) 2019 The Android Open Source Project
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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Internal.Util
{
    [TestClass]
    public class FileChannelDataSourceTest
    {
        [TestMethod]
        public void testFeedsCorrectData_whenFilePartiallyReadFromBeginning()
        {
            byte[] fullFileContent = createFileContent(1024 * 1024 + 987654);
            RandomAccessFile raf = createRaf(fullFileContent);
            DataSource rafDataSource = new FileChannelDataSource(raf.getChannel());

            ByteArrayDataSink dataSink = new ByteArrayDataSink();

            int bytesToFeed = 1024 * 1024 + 12345;
            rafDataSource.feed(0, bytesToFeed, dataSink);


            byte[] expectedBytes = new byte[bytesToFeed];
            Buffer.BlockCopy(fullFileContent, 0, expectedBytes, 0, bytesToFeed);

            byte[] resultBytes = getDataSinkBytes(dataSink);

            assertArrayEquals(expectedBytes, resultBytes);
        }

        [TestMethod]
        public void testFeedsCorrectData_whenFilePartiallyReadWithOffset()
        {
            byte[] fullFileContent = createFileContent(1024 * 1024 + 987654);
            RandomAccessFile raf = createRaf(fullFileContent);
            DataSource rafDataSource = new FileChannelDataSource(raf.getChannel());

            ByteArrayDataSink dataSink = new ByteArrayDataSink();

            int offset = 23456;
            int bytesToFeed = 1024 * 1024 + 12345;
            rafDataSource.feed(offset, bytesToFeed, dataSink);

            byte[] expectedBytes = new byte[bytesToFeed];
            Buffer.BlockCopy(fullFileContent, offset, expectedBytes, 0, bytesToFeed);

            byte[] resultBytes = getDataSinkBytes(dataSink);

            assertArrayEquals(expectedBytes, resultBytes);
        }

        [TestMethod]
        public void testFeedsCorrectData_whenSeveralMbRead()
        {
            byte[] fullFileContent = createFileContent(3 * 1024 * 1024 + 987654);
            RandomAccessFile raf = createRaf(fullFileContent);
            DataSource rafDataSource = new FileChannelDataSource(raf.getChannel());

            ByteArrayDataSink dataSink = new ByteArrayDataSink();

            int offset = 23456;
            int bytesToFeed = 2 * 1024 * 1024 + 12345;
            rafDataSource.feed(offset, bytesToFeed, dataSink);

            byte[] expectedBytes = new byte[bytesToFeed];
            Buffer.BlockCopy(fullFileContent, offset, expectedBytes, 0, bytesToFeed);

            byte[] resultBytes = getDataSinkBytes(dataSink);

            assertArrayEquals(expectedBytes, resultBytes);
        }

        private static byte[] getDataSinkBytes(ByteArrayDataSink dataSink)
        {
            ByteBuffer result = dataSink.getByteBuffer(0, (int)dataSink.size());
            byte[] resultBytes = new byte[result.limit()];
            result.get(resultBytes);
            return resultBytes;
        }

        private static byte[] createFileContent(int fileSize)
        {
            byte[] fullFileContent = new byte[fileSize];
            for (int i = 0; i < fileSize; ++i)
            {
                fullFileContent[i] = (byte)(i % 255);
            }

            return fullFileContent;
        }

        private RandomAccessFile createRaf(byte[] content)
        {
            var dataFile = Path.GetTempFileName();
            File.WriteAllBytes(dataFile, content);
            return new RandomAccessFile(new FileInfo(dataFile), "r");
        }
    }
}