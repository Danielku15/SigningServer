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

using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.Test.ApkSig.Util
{
    /**
     * Tests for the {@link DataSource} returned by {@link DataSources#asDataSource(ByteBuffer)}.
     */
    public class DataSourceFromByteBufferTest : DataSourceTestBase
    {
        [TestMethod]
        public void testChangesToBufferPosAndLimitNotVisible()
        {
            ByteBuffer buf = ByteBuffer.wrap(Encoding.UTF8.GetBytes("abcdefgh"));
            buf.position(1);
            buf.limit(4);
            DataSource ds = DataSources.asDataSource(buf);
            buf.position(2);
            buf.limit(buf.capacity());
            assertGetByteBufferEquals("bcd", ds, 0, (int)ds.size());
            assertFeedEquals("bcd", ds, 0, (int)ds.size());
            assertSliceEquals("bcd", ds, 0, (int)ds.size());
            assertCopyToEquals("bcd", ds, 0, (int)ds.size());
        }

        protected override CloseableWithDataSource createDataSource(byte[] contents)
        {
            return CloseableWithDataSource.of(DataSources.asDataSource(ByteBuffer.wrap(contents)));
        }
    }
}