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
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /**
     * Growable byte array which can be appended to via {@link DataSink} interface and read from via
     * {@link DataSource} interface.
     */
    public class ByteArrayDataSink : ReadableDataSink
    {
        private static readonly int MAX_READ_CHUNK_SIZE = 65536;
        private byte[] mArray;
        private int mSize;

        public ByteArrayDataSink()
            : this(65536)
        {
        }

        public ByteArrayDataSink(int initialCapacity)
        {
            if (initialCapacity < 0)
            {
                throw new ArgumentException("initial capacity: " + initialCapacity);
            }

            mArray = new byte[initialCapacity];
        }

        public void consume(byte[] buf, int offset, int length)
        {
            if (offset < 0)
            {
                // Must perform this check because System.arraycopy below doesn't perform it when
                // length == 0
                throw new IndexOutOfRangeException("offset: " + offset);
            }

            if (offset > buf.Length)
            {
                // Must perform this check because System.arraycopy below doesn't perform it when
                // length == 0
                throw new IndexOutOfRangeException(
                    "offset: " + offset + ", buf.length: " + buf.Length);
            }

            if (length == 0)
            {
                return;
            }

            ensureAvailable(length);
            Array.Copy(buf, offset, mArray, mSize, length);
            mSize += length;
        }


        public void consume(ByteBuffer buf)
        {
            if (!buf.hasRemaining())
            {
                return;
            }

            if (buf.hasArray())
            {
                consume(buf.array(), buf.arrayOffset() + buf.position(), buf.remaining());
                buf.position(buf.limit());
                return;
            }

            ensureAvailable(buf.remaining());
            byte[] tmp = new byte[Math.Min(buf.remaining(), MAX_READ_CHUNK_SIZE)];
            while (buf.hasRemaining())
            {
                int chunkSize = Math.Min(buf.remaining(), tmp.Length);
                buf.get(tmp, 0, chunkSize);
                Array.Copy(tmp, 0, mArray, mSize, chunkSize);
                mSize += chunkSize;
            }
        }

        private void ensureAvailable(int minAvailable)
        {
            if (minAvailable <= 0)
            {
                return;
            }

            long minCapacity = ((long)mSize) + minAvailable;
            if (minCapacity <= mArray.Length)
            {
                return;
            }

            if (minCapacity > int.MaxValue)
            {
                throw new IOException(
                    "Required capacity too large: " + minCapacity + ", max: " + int.MaxValue);
            }

            int doubleCurrentSize = (int)Math.Min(mArray.Length * 2L, int.MaxValue);
            int newSize = (int)Math.Max(minCapacity, doubleCurrentSize);
            Array.Resize(ref mArray, newSize);
        }


        public long size()
        {
            return mSize;
        }


        public ByteBuffer getByteBuffer(long offset, int size)
        {
            checkChunkValid(offset, size);

            // checkChunkValid ensures that it's OK to cast offset to int.
            return ByteBuffer.wrap(mArray, (int)offset, size).slice();
        }


        public void feed(long offset, long size, DataSink sink)
        {
            checkChunkValid(offset, size);

            // checkChunkValid ensures that it's OK to cast offset and size to int.
            sink.consume(mArray, (int)offset, (int)size);
        }


        public void copyTo(long offset, int size, ByteBuffer dest)
        {
            checkChunkValid(offset, size);

            // checkChunkValid ensures that it's OK to cast offset to int.
            dest.put(mArray, (int)offset, size);
        }

        private void checkChunkValid(long offset, long size)
        {
            if (offset < 0)
            {
                throw new IndexOutOfRangeException("offset: " + offset);
            }

            if (size < 0)
            {
                throw new IndexOutOfRangeException("size: " + size);
            }

            if (offset > mSize)
            {
                throw new IndexOutOfRangeException(
                    "offset (" + offset + ") > source size (" + mSize + ")");
            }

            long endOffset = offset + size;
            if (endOffset < offset)
            {
                throw new IndexOutOfRangeException(
                    "offset (" + offset + ") + size (" + size + ") overflow");
            }

            if (endOffset > mSize)
            {
                throw new IndexOutOfRangeException(
                    "offset (" + offset + ") + size (" + size + ") > source size (" + mSize + ")");
            }
        }


        public DataSource slice(long offset, long size)
        {
            checkChunkValid(offset, size);
            // checkChunkValid ensures that it's OK to cast offset and size to int.
            return new SliceDataSource(this, (int)offset, (int)size);
        }

        /**
     * Slice of the growable byte array. The slice's offset and size in the array are fixed.
     */
        private class SliceDataSource : DataSource
        {
            private readonly ByteArrayDataSink mSink;
            private readonly int mSliceOffset;
            private readonly int mSliceSize;

            public SliceDataSource(ByteArrayDataSink sink, int offset, int size)
            {
                mSink = sink;
                mSliceOffset = offset;
                mSliceSize = size;
            }

            public long size()
            {
                return mSliceSize;
            }

            public void feed(long offset, long size, DataSink sink)
            {
                checkChunkValid(offset, size);

// checkChunkValid combined with the way instances of this class are constructed ensures
// that mSliceOffset + offset does not overflow and that it's fine to cast size to int.
                sink.consume(mSink.mArray, (int)(mSliceOffset + offset), (int)size);
            }


            public ByteBuffer getByteBuffer(long offset, int size)
            {
                checkChunkValid(offset, size);
                // checkChunkValid combined with the way instances of this class are constructed ensures
                // that mSliceOffset + offset does not overflow.
                return ByteBuffer.wrap(mSink.mArray, (int)(mSliceOffset + offset), size).slice();
            }


            public void copyTo(long offset, int size, ByteBuffer dest)
            {
                checkChunkValid(offset, size);

                // checkChunkValid combined with the way instances of this class are constructed ensures
                // that mSliceOffset + offset does not overflow.
                dest.put(mSink.mArray, (int)(mSliceOffset + offset), size);
            }


            public DataSource slice(long offset, long size)
            {
                checkChunkValid(offset, size);
                // checkChunkValid combined with the way instances of this class are constructed ensures
                // that mSliceOffset + offset does not overflow and that it's fine to cast size to int.
                return new SliceDataSource(mSink, (int)(mSliceOffset + offset), (int)size);
            }

            private void checkChunkValid(long offset, long size)
            {
                if (offset < 0)
                {
                    throw new IndexOutOfRangeException("offset: " + offset);
                }

                if (size < 0)
                {
                    throw new IndexOutOfRangeException("size: " + size);
                }

                if (offset > mSliceSize)
                {
                    throw new IndexOutOfRangeException(
                        "offset (" + offset + ") > source size (" + mSliceSize + ")");
                }

                long endOffset = offset + size;
                if (endOffset < offset)
                {
                    throw new IndexOutOfRangeException(
                        "offset (" + offset + ") + size (" + size + ") overflow");
                }

                if (endOffset > mSliceSize)
                {
                    throw new IndexOutOfRangeException(
                        "offset (" + offset + ") + size (" + size + ") > source size (" + mSliceSize
                        + ")");
                }
            }
        }
    }
}