using System;
using System.IO;
using SigningServer.Android.IO.Channels;

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

        public void Write(sbyte[] buf, int offset, int length)
        {
            mStream.Write(buf.AsBytes(), offset, length);
        }

        public void Write(sbyte[] buf)
        {
            mStream.Write(buf.AsBytes(), 0, buf.Length);
        }

        public long Length()
        {
            return mStream.Length;
        }

        public void SetLength(int i)
        {
            mStream.SetLength(i);
        }

        public void ReadFully(sbyte[] contents)
        {
            mStream.Read(contents.AsBytes(), 0, contents.Length);
        }
    }
}