/*
 * Copyright (C) 2016 The Android Open Source Project
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

using System.IO;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.Test.ApkSig.Util
{
    /**
     * Tests for the {@link DataSink} returned by
     * {@link DataSinks#asDataSink(java.io.RandomAccessFile)}.
     */
    public class DataSinkFromRAFTest : DataSinkTestBase<RandomAccessFileDataSink>
    {
        protected override CloseableWithDataSink createDataSink()
        {
            var tmp = new FileInfo(Path.GetTempFileName());
            RandomAccessFile f = null;
            try
            {
                f = new RandomAccessFile(tmp, "rw");
            }
            finally
            {
                if (f == null)
                {
                    tmp.Delete();
                }
            }

            return CloseableWithDataSink.of(
                (RandomAccessFileDataSink)DataSinks.asDataSink(f),
                new DataSourceFromRAFTest.TmpFileCloseable(tmp, f));
        }


        protected override ByteBuffer
            getContents(RandomAccessFileDataSink dataSink)
        {
            RandomAccessFile f = dataSink.getFile(
            );

            if (f.length() > int.MaxValue)
            {
                throw new IOException("File too large: " + f.length());
            }

            byte[] contents = new byte[(int)f.length()];
            f.seek(0);
            f.readFully(contents);
            return ByteBuffer.wrap(contents);
        }
    }
}