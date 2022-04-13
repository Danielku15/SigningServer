// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    /// <summary>
    /// {@link DataSource} backed by a {@link ByteBuffer}.
    /// </summary>
    public class ByteBufferDataSource: SigningServer.Android.Com.Android.Apksig.Util.DataSource
    {
        internal readonly SigningServer.Android.IO.ByteBuffer mBuffer;
        
        internal readonly int mSize;
        
        /// <summary>
        /// Constructs a new {@code ByteBufferDigestSource} based on the data contained in the provided
        /// buffer between the buffer's position and limit.
        /// </summary>
        public ByteBufferDataSource(SigningServer.Android.IO.ByteBuffer buffer)
            : base (buffer, true)
        {
            ;
        }
        
        /// <summary>
        /// Constructs a new {@code ByteBufferDigestSource} based on the data contained in the provided
        /// buffer between the buffer's position and limit.
        /// </summary>
        internal ByteBufferDataSource(SigningServer.Android.IO.ByteBuffer buffer, bool sliceRequired)
        {
            mBuffer = (sliceRequired) ? buffer.Slice() : buffer;
            mSize = buffer.Remaining();
        }
        
        public override long Size()
        {
            return mSize;
        }
        
        public override SigningServer.Android.IO.ByteBuffer GetByteBuffer(long offset, int size)
        {
            CheckChunkValid(offset, size);
            int chunkPosition = (int)offset;
            int chunkLimit = chunkPosition + size;
            lock(mBuffer)
            {
                mBuffer.Position(0);
                mBuffer.Limit(chunkLimit);
                mBuffer.Position(chunkPosition);
                return mBuffer.Slice();
            }
        }
        
        public override void CopyTo(long offset, int size, SigningServer.Android.IO.ByteBuffer dest)
        {
            dest.Put(GetByteBuffer(offset, size));
        }
        
        public override void Feed(long offset, long size, SigningServer.Android.Com.Android.Apksig.Util.DataSink sink)
        {
            if ((size < 0) || (size > mSize))
            {
                throw new System.IndexOutOfRangeException("size: " + size + ", source size: " + mSize);
            }
            sink.Consume(GetByteBuffer(offset, (int)size));
        }
        
        public override SigningServer.Android.Com.Android.Apksig.Internal.Util.ByteBufferDataSource Slice(long offset, long size)
        {
            if ((offset == 0) && (size == mSize))
            {
                return this;
            }
            if ((size < 0) || (size > mSize))
            {
                throw new System.IndexOutOfRangeException("size: " + size + ", source size: " + mSize);
            }
            return new SigningServer.Android.Com.Android.Apksig.Internal.Util.ByteBufferDataSource(GetByteBuffer(offset, (int)size), false);
        }
        
        internal void CheckChunkValid(long offset, long size)
        {
            if (offset < 0)
            {
                throw new System.IndexOutOfRangeException("offset: " + offset);
            }
            if (size < 0)
            {
                throw new System.IndexOutOfRangeException("size: " + size);
            }
            if (offset > mSize)
            {
                throw new System.IndexOutOfRangeException("offset (" + offset + ") > source size (" + mSize + ")");
            }
            long endOffset = offset + size;
            if (endOffset < offset)
            {
                throw new System.IndexOutOfRangeException("offset (" + offset + ") + size (" + size + ") overflow");
            }
            if (endOffset > mSize)
            {
                throw new System.IndexOutOfRangeException("offset (" + offset + ") + size (" + size + ") > source size (" + mSize + ")");
            }
        }
        
    }
    
}
