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
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /**
     * {@link DataSource} backed by a {@link ByteBuffer}.
     */
    public class ByteBufferDataSource : DataSource
    {
        private readonly ByteBuffer mBuffer;
        private readonly int mSize;

        /**
         * Constructs a new {@code ByteBufferDigestSource} based on the data contained in the provided
         * buffer between the buffer's position and limit.
         */
        public ByteBufferDataSource(ByteBuffer buffer)
            : this(buffer, true)
        {
        }

        /**
     * Constructs a new {@code ByteBufferDigestSource} based on the data contained in the provided
     * buffer between the buffer's position and limit.
     */
        private ByteBufferDataSource(ByteBuffer buffer, bool sliceRequired)
        {
            mBuffer = (sliceRequired) ? buffer.slice() : buffer;
            mSize = buffer.remaining();
        }


        public long size()
        {
            return mSize;
        }


        public ByteBuffer getByteBuffer(long offset, int size)
        {
            checkChunkValid(offset, size);

            // checkChunkValid ensures that it's OK to cast offset to int.
            int chunkPosition = (int)offset;
            int chunkLimit = chunkPosition + size;
            // Creating a slice of ByteBuffer modifies the state of the source ByteBuffer (position
            // and limit fields, to be more specific). We thus use synchronization around these
            // state-changing operations to make instances of this class thread-safe.
            lock (mBuffer)
            {
                // ByteBuffer.limit(int) and .position(int) check that that the position >= limit
                // invariant is not broken. Thus, the only way to safely change position and limit
                // without caring about their current values is to first set position to 0 or set the
                // limit to capacity.
                mBuffer.position(0);

                mBuffer.limit(chunkLimit);
                mBuffer.position(chunkPosition);
                return mBuffer.slice();
            }
        }


        public void copyTo(long offset, int size, ByteBuffer dest)
        {
            dest.put(getByteBuffer(offset, size));
        }


        public void feed(long offset, long size, DataSink sink)
        {
            if ((size < 0) || (size > mSize))
            {
                throw new IndexOutOfRangeException("size: " + size + ", source size: " + mSize);
            }

            sink.consume(getByteBuffer(offset, (int)size));
        }


        public DataSource slice(long offset, long size)
        {
            if ((offset == 0) && (size == mSize))
            {
                return this;
            }

            if ((size < 0) || (size > mSize))
            {
                throw new IndexOutOfRangeException("size: " + size + ", source size: " + mSize);
            }

            return new ByteBufferDataSource(
                getByteBuffer(offset, (int)size),
                false // no need to slice -- it's already a slice
            );
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
    }
}