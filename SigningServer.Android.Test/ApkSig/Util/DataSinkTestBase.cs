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
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Util
{
    /**
     * Base class for testing implementations of {@link DataSink}. This class tests the contract of
     * {@code DataSink}.
     *
     * <p>To subclass, provide an implementation of {@link #createDataSink()} which returns the
     * implementation of {@code DataSink} you want to test.
     */
    public abstract class DataSinkTestBase<T> where T : DataSink
    {
        /**
         * Returns a new {@link DataSink}.
         */
        protected abstract CloseableWithDataSink createDataSink();

        /**
         * Returns the contents of the data sink.
         */
        protected abstract ByteBuffer getContents(T dataSink);

        [TestMethod]
        public void testConsumeFromArray()
        {
            using (CloseableWithDataSink c = createDataSink())
            {
                T sink = c.getDataSink();
                byte[] input = Encoding.UTF8.GetBytes("abcdefg");
                sink.consume(input, 2, 3); // "cde"
                sink.consume(input, 0, 1); // "a"
                assertContentsEquals("cdea", sink);

                // Zero-length chunks
                sink.consume(input, 0, 0);
                sink.consume(input, 1, 0);
                sink.consume(input, input.Length - 2, 0);
                sink.consume(input, input.Length - 1, 0);
                sink.consume(input, input.Length, 0);

                // Invalid chunks
                assertConsumeArrayThrowsIOOB(sink, input, -1, 0);
                assertConsumeArrayThrowsIOOB(sink, input, -1, 3);
                assertConsumeArrayThrowsIOOB(sink, input, 0, input.Length + 1);
                assertConsumeArrayThrowsIOOB(sink, input, input.Length - 2, 4);
                assertConsumeArrayThrowsIOOB(sink, input, input.Length + 1, 0);
                assertConsumeArrayThrowsIOOB(sink, input, input.Length + 1, 1);

                assertContentsEquals("cdea", sink);
            }
        }

        [TestMethod]
        public void testConsumeFromByteBuffer()
        {
            using (CloseableWithDataSink c = createDataSink())
            {
                T sink = c.getDataSink();
                ByteBuffer input = ByteBuffer.wrap(Encoding.UTF8.GetBytes("abcdefg"));
                input.position(2);
                input.limit(5);
                sink.consume(input); // "cde"
                assertEquals(5, input.position());
                assertEquals(5, input.limit());

                input.position(0);
                input.limit(1);
                sink.consume(input); // "a"
                assertContentsEquals("cdea", sink);

                // Empty input
                sink.consume(input);
                assertContentsEquals("cdea", sink);

                // ByteBuffer which isn't backed by a byte[]
                input = ByteBuffer.allocateDirect(2);
                input.put((byte)'X');
                input.put((byte)'Z');
                input.flip();
                sink.consume(input);

                assertContentsEquals("cdeaXZ", sink);
                assertEquals(2, input.position());
                assertEquals(2, input.limit());

                // Empty input
                sink.consume(input);
                assertContentsEquals("cdeaXZ", sink);
            }
        }

        /**
     * Returns the contents of the provided buffer as a string. The buffer's position and limit
     * remain unchanged.
     */
        private static String toString(ByteBuffer buf)
        {
            return DataSourceTestBase.toString(buf);
        }

        private void assertContentsEquals(String expectedContents, T sink)
        {
            ByteBuffer actual = getContents(sink);
            assertEquals(expectedContents, toString(actual));
        }

        private static void assertConsumeArrayThrowsIOOB(
            DataSink sink, byte[] arr, int offset, int length)

        {
            try
            {
                sink.consume(arr, offset, length);
                fail();
            }
            catch (ArgumentOutOfRangeException expected)
            {
            }
        }

        public class CloseableWithDataSink : IDisposable
        {
            private T mDataSink;
            private IDisposable mCloseable;

            private CloseableWithDataSink(T
                dataSink, IDisposable closeable)
            {
                mDataSink = dataSink;
                mCloseable = closeable;
            }

            public static CloseableWithDataSink of(T dataSink)
            {
                return new CloseableWithDataSink(dataSink, null);
            }

            public static CloseableWithDataSink of(
                T dataSink, IDisposable closeable)
            {
                return new CloseableWithDataSink(dataSink, closeable);
            }

            public T getDataSink()
            {
                return mDataSink;
            }

            public IDisposable getCloseable()
            {
                return mCloseable;
            }

            public void Dispose()
            {
                if (mCloseable != null)
                {
                    mCloseable.Dispose();
                }
            }
        }
    }
}