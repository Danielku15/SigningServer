// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    /// <summary>
    /// {@link DataSink} which outputs received data into the associated file, sequentially.
    /// </summary>
    public class RandomAccessFileDataSink: SigningServer.Android.Com.Android.Apksig.Util.DataSink
    {
        internal readonly SigningServer.Android.IO.RandomAccessFile mFile;
        
        internal readonly SigningServer.Android.IO.Channels.FileChannel mFileChannel;
        
        internal long mPosition;
        
        /// <summary>
        /// Constructs a new {@code RandomAccessFileDataSink} which stores output starting from the
        /// beginning of the provided file.
        /// </summary>
        public RandomAccessFileDataSink(SigningServer.Android.IO.RandomAccessFile file)
            : base (file, 0)
        {
            ;
        }
        
        /// <summary>
        /// Constructs a new {@code RandomAccessFileDataSink} which stores output starting from the
        /// specified position of the provided file.
        /// </summary>
        public RandomAccessFileDataSink(SigningServer.Android.IO.RandomAccessFile file, long startPosition)
        {
            if (file == null)
            {
                throw new System.NullReferenceException("file == null");
            }
            if (startPosition < 0)
            {
                throw new System.ArgumentException("startPosition: " + startPosition);
            }
            mFile = file;
            mFileChannel = file.GetChannel();
            mPosition = startPosition;
        }
        
        /// <summary>
        /// Returns the underlying {@link RandomAccessFile}.
        /// </summary>
        public virtual SigningServer.Android.IO.RandomAccessFile GetFile()
        {
            return mFile;
        }
        
        public override void Consume(sbyte[] buf, int offset, int length)
        {
            if (offset < 0)
            {
                throw new System.IndexOutOfRangeException("offset: " + offset);
            }
            if (offset > buf.Length)
            {
                throw new System.IndexOutOfRangeException("offset: " + offset + ", buf.length: " + buf.Length);
            }
            if (length == 0)
            {
                return;
            }
            lock(mFile)
            {
                mFile.Seek(mPosition);
                mFile.Write(buf, offset, length);
                mPosition += length;
            }
        }
        
        public override void Consume(SigningServer.Android.IO.ByteBuffer buf)
        {
            int length = buf.Remaining();
            if (length == 0)
            {
                return;
            }
            lock(mFile)
            {
                mFile.Seek(mPosition);
                while (buf.HasRemaining())
                {
                    mFileChannel.Write(buf);
                }
                mPosition += length;
            }
        }
        
    }
    
}
