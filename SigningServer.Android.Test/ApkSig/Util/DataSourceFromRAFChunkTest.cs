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
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.Test.ApkSig.Util
{
    /**
     * Tests for the {@link DataSource} returned by
     * {@link DataSources#asDataSource(RandomAccessFile, long, long)}.
     */
    [TestClass]
    public class DataSourceFromRAFChunkTest : DataSourceTestBase
    {
        [TestMethod]
        public void testFileSizeChangesNotVisible()
        {
            using (CloseableWithDataSource c = createDataSource("abcdefg"))
            {
                DataSource ds = c.getDataSource();
                DataSource slice = ds.slice(3, 2);
                FileInfo f = ((DataSourceFromRAFTest.TmpFileCloseable)c.getCloseable()).getFile();
                assertGetByteBufferEquals("abcdefg", ds, 0, (int)ds.size());
                assertGetByteBufferEquals("de", slice, 0, (int)slice.size());
                assertFeedEquals("cdefg", ds, 2, 5);
                assertFeedEquals("e", slice, 1, 1);
                assertCopyToEquals("cdefg", ds, 2, 5);
                assertCopyToEquals("e", slice, 1, 1);
                assertSliceEquals("cdefg", ds, 2, 5);
                assertSliceEquals("e", slice, 1, 1);
                using (RandomAccessFile raf = new RandomAccessFile(f, "rw"))
                {
                    raf.seek(raf.length());
                    raf.write(Encoding.UTF8.GetBytes("hijkl"));
                }

                assertGetByteBufferEquals("abcdefg", ds, 0, (int)ds.size());
                assertGetByteBufferEquals("de", slice, 0, (int)slice.size());
                assertGetByteBufferThrowsIOOB(ds, 0, (int)ds.size() + 3);
                assertFeedThrowsIOOB(ds, 0, (int)ds.size() + 3);
                assertSliceThrowsIOOB(ds, 0, (int)ds.size() + 3);
                assertCopyToThrowsIOOB(ds, 0, (int)ds.size() + 3);
            }
        }

        protected override CloseableWithDataSource createDataSource(byte[] contents)
        {
            // "01" | contents | "9"
            byte[] fullContents = new byte[2 + contents.Length + 1];
            fullContents[0] = (byte)'0';
            fullContents[1] = (byte)'1';
            Array.Copy(contents, 0, fullContents, 2, contents.Length);
            fullContents[fullContents.Length - 1] = (byte)'9';

            FileInfo tmp = new FileInfo(Path.GetTempFileName());
            RandomAccessFile f = null;
            try
            {
                File.WriteAllBytes(tmp.FullName, fullContents);
                f = new RandomAccessFile(tmp, "r");
            }
            finally
            {
                if (f == null)
                {
                    tmp.Delete();
                }
            }

            return CloseableWithDataSource.of(
                createDataSource(f, 2, contents.Length),
                new DataSourceFromRAFTest.TmpFileCloseable(tmp, f));
        }

        protected virtual DataSource createDataSource(RandomAccessFile f, int offset, int length)
        {
            return DataSources.asDataSource(f, offset, length);
        }
    }
}