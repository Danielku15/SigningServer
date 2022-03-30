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
using System.Collections.Generic;
using System.Linq;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /** Pseudo {@link DataSource} that chains the given {@link DataSource} as a continuous one. */
    public class ChainedDataSource : DataSource
    {
        private readonly DataSource[] mSources;
        private readonly long mTotalSize;

        public ChainedDataSource(params DataSource[] sources)
        {
            mSources = sources;
            mTotalSize = sources.Sum(s => s.size());
        }


        public long size()
        {
            return mTotalSize;
        }

        public void feed(long offset, long size, DataSink sink)
        {
            if (offset + size > mTotalSize)
            {
                throw new IndexOutOfRangeException("Requested more than available");
            }

            foreach (DataSource src in mSources)
            {
                // Offset is beyond the current source. Skip.
                if (offset >= src.size())
                {
                    offset -= src.size();
                    continue;
                }

                // If the remaining is enough, finish it.
                long remaining = src.size() - offset;
                if (remaining >= size)
                {
                    src.feed(offset, size, sink);
                    break;
                }

                // If the remaining is not enough, consume all.
                src.feed(offset, remaining, sink);
                size -= remaining;
                offset = 0;
            }
        }

        public ByteBuffer getByteBuffer(long offset, int size)
        {
            if (offset + size > mTotalSize)
            {
                throw new IndexOutOfRangeException("Requested more than available");
            }

            // Skip to the first DataSource we need.
            Tuple<int, long> firstSource = locateDataSource(offset);
            int i = firstSource.Item1;
            offset = firstSource.Item2;

            // Return the current source's ByteBuffer if it fits.
            if (offset + size <= mSources[i].size())
            {
                return mSources[i].getByteBuffer(offset, size);
            }

            // Otherwise, read into a new buffer.
            ByteBuffer buffer = ByteBuffer.allocate(size);
            for (;
                 i < mSources.Length && buffer.hasRemaining();
                 i++)
            {
                long sizeToCopy = Math.Min(mSources[i].size() - offset, buffer.remaining());
                mSources[i].copyTo(offset, (int)(sizeToCopy), buffer);
                offset = 0; // may not be zero for the first source, but reset after that.
            }

            buffer.rewind();
            return buffer;
        }

        public void copyTo(long offset, int size, ByteBuffer dest)
        {
            feed(offset, size, new ByteBufferSink(dest));
        }

        public DataSource slice(long offset, long size)
        {
            // Find the first slice.
            Tuple<int, long> firstSource = locateDataSource(offset);
            int beginIndex = firstSource.Item1;
            long beginLocalOffset = firstSource.Item2;
            DataSource beginSource = mSources[beginIndex];

            if (beginLocalOffset + size <= beginSource.size())
            {
                return beginSource.slice(beginLocalOffset, size);
            }

            // Add the first slice to chaining, followed by the middle full slices, then the last.
            List<DataSource> sources = new List<DataSource>();
            sources.Add(beginSource.slice(
                beginLocalOffset, beginSource.size() - beginLocalOffset));

            Tuple<int, long> lastSource = locateDataSource(offset + size - 1);
            int endIndex = lastSource.Item1;
            long endLocalOffset = lastSource.Item2;

            for (int i = beginIndex + 1; i < endIndex; i++)
            {
                sources.Add(mSources[i]);
            }

            sources.Add(mSources[endIndex].slice(0, endLocalOffset + 1));
            return new ChainedDataSource(sources.ToArray());
        }

        /**
     * Find the index of DataSource that offset is at.
     * @return Pair of DataSource index and the local offset in the DataSource.
     */
        private Tuple<int, long> locateDataSource(long offset)
        {
            long localOffset = offset;
            for (int i = 0; i < mSources.Length; i++)
            {
                if (localOffset < mSources[i].size())
                {
                    return Tuple.Create(i, localOffset);
                }

                localOffset -= mSources[i].size();
            }

            throw new IndexOutOfRangeException("Access is out of bound, offset: " + offset +
                                               ", totalSize: " + mTotalSize);
        }
    }
}