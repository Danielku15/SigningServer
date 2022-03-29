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

using System;
using System.IO;
using SigningServer.Android;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /**
     * {@link DataSink} which outputs received data into the associated file, sequentially.
     */
    public class RandomAccessFileDataSink : DataSink
    {
        private readonly RandomAccessFile mFile;
        private readonly FileChannel mFileChannel;
        private long mPosition;

        /**
     * Constructs a new {@code RandomAccessFileDataSink} which stores output starting from the
     * beginning of the provided file.
     */
        public RandomAccessFileDataSink(RandomAccessFile file)
            : this(file, 0)
        {
        }

        /**
     * Constructs a new {@code RandomAccessFileDataSink} which stores output starting from the
     * specified position of the provided file.
     */
        public RandomAccessFileDataSink(RandomAccessFile file, long startPosition)
        {
            if (startPosition < 0)
            {
                throw new ArgumentException("startPosition: " + startPosition);
            }

            mFile = file ?? throw new ArgumentNullException(nameof(file));
            mFileChannel = file.getChannel();
            mPosition = startPosition;
        }

        /**
     * Returns the underlying {@link RandomAccessFile}.
     */
        public RandomAccessFile getFile()
        {
            return mFile;
        }

        public void consume(byte[] buf, int offset, int length)
        {
            if (offset < 0)
            {
                // Must perform this check here because RandomAccessFile.write doesn't throw when offset
                // is negative but length is 0
                throw new IndexOutOfRangeException("offset: " + offset);
            }

            if (offset > buf.Length)
            {
                // Must perform this check here because RandomAccessFile.write doesn't throw when offset
                // is too large but length is 0
                throw new IndexOutOfRangeException(
                    "offset: " + offset + ", buf.length: " + buf.Length);
            }

            if (length == 0)
            {
                return;
            }

            lock (mFile)
            {
                mFile.seek(mPosition);
                mFile.write(buf, offset, length);
                mPosition += length;
            }
        }

        public void consume(ByteBuffer buf)
        {
            int length = buf.remaining();
            if (length == 0)
            {
                return;
            }

            lock (mFile)
            {
                mFile.seek(mPosition);
                while (buf.hasRemaining())
                {
                    mFileChannel.write(buf);
                }

                mPosition += length;
            }
        }
    }
}