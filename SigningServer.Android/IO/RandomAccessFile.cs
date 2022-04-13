using System;
using System.IO;

namespace SigningServer.Android.IO
{
    public class RandomAccessFile : IDisposable
    {
        private readonly FileStream mStream;

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
            return new FileChannel(mStream);
        }

        public void Seek(long position)
        {
            mStream.Seek(position, SeekOrigin.Begin);
        }

        public void Write(byte[] buf, int offset, int length)
        {
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

    public class FileChannel
    {
        private readonly FileStream mStream;

        public FileChannel(FileStream stream)
        {
            mStream = stream;
        }

        public long Size()
        {
            return mStream.Length;
        }

        public void Position(long position)
        {
            mStream.Seek(position, SeekOrigin.Begin);
        }

        public int Read(ByteBuffer buf)
        {
            var rem = buf.Remaining();
            var x = new byte[rem];
            var actual = mStream.Read(x, 0, rem);

            buf.Put(x, 0, actual);
            return actual;
        }

        public void Write(ByteBuffer buf)
        {
            var x = new byte[buf.Remaining()];
            buf.Get(x);
            mStream.Write(x, 0, x.Length);
        }
    }
}