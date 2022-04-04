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
using SigningServer.Android.Test.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Util
{
    /**
     * Tests for the {@link DataSource} returned by
     * {@link DataSources#asDataSource(java.io.RandomAccessFile)}.
     */
    [TestClass]
    public class DataSourceFromRAFTest : DataSourceTestBase
    {
        [TestMethod]
        public void testFileSizeChangesVisible()
        {
            using (CloseableWithDataSource c = createDataSource("abcdefg"))
            {
                DataSource ds = c.getDataSource();
                DataSource slice = ds.slice(3, 2);
                FileInfo f = ((TmpFileCloseable)c.getCloseable()).getFile();
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
                    raf.seek(7);
                    raf.write(Encoding.UTF8.GetBytes("hijkl"));
                }

                assertEquals(12, ds.size());
                assertGetByteBufferEquals("abcdefghijkl", ds, 0, (int)ds.size());
                assertGetByteBufferEquals("de", slice, 0, (int)slice.size());
                assertFeedEquals("cdefg", ds, 2, 5);
                assertFeedEquals("fgh", ds, 5, 3);
                assertCopyToEquals("fgh", ds, 5, 3);
                assertSliceEquals("fgh", ds, 5, 3);
            }
        }

        protected override CloseableWithDataSource
            createDataSource(byte[] contents)
        {
            FileInfo tmp = new FileInfo(Path.GetTempFileName());

            RandomAccessFile f = null;
            try
            {
                File.WriteAllBytes(tmp.FullName, contents);
                f = new RandomAccessFile(tmp, "r");
            }
            finally
            {
                if (f == null)
                {
                    tmp.Delete();
                }
            }

            return DataSourceTestBase.CloseableWithDataSource.of(
                createDataSource(f),
                new TmpFileCloseable(tmp, f));
        }

        protected virtual DataSource createDataSource(RandomAccessFile randomAccessFile)
        {
            return DataSources.asDataSource(randomAccessFile);
        }

        /**
         * {@link Closeable} which closes the delegate {@code Closeable} and deletes the provided file.
         */
        public class TmpFileCloseable : IDisposable
        {
            private readonly FileInfo mFile;
            private readonly IDisposable mDelegate;

            public TmpFileCloseable(FileInfo file, IDisposable closeable)
            {
                mFile = file;
                mDelegate = closeable;
            }

            public FileInfo getFile()
            {
                return mFile;
            }

            public void Dispose()
            {
                try
                {
                    if (mDelegate != null)
                    {
                        mDelegate.Dispose();
                    }
                }
                finally

                {
                    if (mFile != null)
                    {
                        mFile.Delete();
                    }
                }
            }
        }
    }
}