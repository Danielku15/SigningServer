using System;
using System.IO;
using SigningServer.Android.IO.Channels;

namespace SigningServer.Android.IO
{
    public class RandomAccessFile : IDisposable
    {
        private readonly FileStream _stream;
        private FileChannel _fileChannel;

        public RandomAccessFile(FileInfo file, string mode)
        {
            if (mode == "r")
            {
                _stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            }
            else if (mode == "rw")
            {
                _stream = file.Open(FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            }
        }

        public void Dispose()
        {
            _stream.Dispose();
        }

        public FileChannel GetChannel()
        {
            var channel = _fileChannel;
            if (channel == null)
            {
                lock (this)
                {
                    channel = _fileChannel;
                    if (channel == null)
                    {
                        channel = new FileChannel(_stream);
                        _fileChannel = channel;
                    }
                }
            }

            return channel;

        }

        public void Seek(long position)
        {
            _stream.Seek(position, SeekOrigin.Begin);
        }

        public void Write(byte[] buf, int offset, int length)
        {
            if (offset < 0 || offset + length > buf.Length)
            {
                throw new IndexOutOfRangeException();
            }
            _stream.Write(buf, offset, length);
        }

        public void Write(byte[] buf)
        {
            _stream.Write(buf, 0, buf.Length);
        }

        public long Length()
        {
            return _stream.Length;
        }

        public void SetLength(int i)
        {
            _stream.SetLength(i);
        }

        public void ReadFully(byte[] contents)
        {
            var unused = _stream.Read(contents, 0, contents.Length);
        }
    }
}
