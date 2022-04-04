using System;
using System.IO;

namespace SigningServer.Android
{
    public class RandomAccessFile : IDisposable
    {
        private readonly FileStream _stream;

        public RandomAccessFile(FileInfo file, string mode)
        {
            if (mode == "r")
            {
                _stream = file.OpenRead();
            }
            else if (mode == "rw")
            {
                _stream = file.Open(FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
            }
        }

        public void Dispose()
        {
            _stream.Dispose();
        }

        public FileChannel getChannel()
        {
            return new FileChannel(_stream);
        }

        public void seek(long position)
        {
            _stream.Seek(position, SeekOrigin.Begin);
        }

        public void write(byte[] buf, int offset, int length)
        {
            _stream.Write(buf, offset, length);
        }

        public long length()
        {
            return _stream.Length;
        }

        public void setLength(int i)
        {
            _stream.SetLength(i);
        }
    }

    public class FileChannel
    {
        private readonly FileStream mStream;

        public FileChannel(FileStream stream)
        {
            mStream = stream;
        }

        public long size()
        {
            return mStream.Length;
        }

        public void position(long position)
        {
            mStream.Seek(position, SeekOrigin.Begin);
        }

        public int read(ByteBuffer buf)
        {
            var rem = buf.remaining();
            var x = new byte[rem];
            var actual = mStream.Read(x, 0, rem);
            buf.put(x, 0, actual);
            return actual;
        }

        public void write(ByteBuffer buf)
        {
            var x = new byte[buf.remaining()];
            buf.get(x);
            mStream.Write(x, 0, x.Length);
        }
    }
}