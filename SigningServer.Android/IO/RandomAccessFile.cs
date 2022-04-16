using System;
using System.IO;
using SigningServer.Android.IO.Channels;

namespace SigningServer.Android.IO
{
    public class RandomAccessFile : IDisposable
    {
        private readonly FileStream mStream;
        private FileChannel mFileChannel;

        public RandomAccessFile(FileInfo file, string mode)
        {
            if (mode == "r")
            {
                mStream = file.Open(FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            }
            else if (mode == "rw")
            {
                mStream = file.Open(FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            }
        }

        public void Dispose()
        {
            mStream.Dispose();
        }

        public FileChannel GetChannel()
        {
            var channel = mFileChannel;
            if (channel == null)
            {
                lock (this)
                {
                    channel = mFileChannel;
                    if (channel == null)
                    {
                        channel = new FileChannel(mStream);
                        mFileChannel = channel;
                    }
                }
            }

            return channel;

        }

        public void Seek(long position)
        {
            mStream.Seek(position, SeekOrigin.Begin);
        }

        public void Write(byte[] buf, int offset, int length)
        {
            if (offset < 0 || offset + length > buf.Length)
            {
                throw new IndexOutOfRangeException();
            }
            mStream.Write(buf, offset, length);
        }

        public void Write(byte[] buf)
        {
            mStream.Write(buf, 0, buf.Length);
        }

        public long Length()
        {
            return mStream.Length;
        }

        public void SetLength(int i)
        {
            mStream.SetLength(i);
        }

        public void ReadFully(byte[] contents)
        {
            mStream.Read(contents, 0, contents.Length);
        }
    }
}