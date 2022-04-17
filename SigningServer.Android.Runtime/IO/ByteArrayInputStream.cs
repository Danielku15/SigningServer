using System.IO;

namespace SigningServer.Android.IO
{
    internal class ByteArrayInputStream : InputStream
    {
        private MemoryStream _in;
        private long _mark;

        public ByteArrayInputStream(byte[] source)
        {
            _in = new MemoryStream(source);
        }

        public void Dispose()
        {
            _in.Dispose();
        }

        public int Read(byte[] buffer, int offset, int len)
        {
            var count = _in.Read(buffer, offset, len);
            return count == 0 ? -1 : count;
        }

        public int Read()
        {
            return _in.ReadByte();
        }

        public int Read(byte[] b)
        {
            return Read(b, 0, b.Length);
        }

        public long Skip(long n)
        {
            var pos = _in.Position;
            var newPos = _in.Seek(n, SeekOrigin.Current);
            return newPos - pos;
        }

        public int Available()
        {
            return (int)(_in.Length - _in.Position);
        }

        public void Mark(int readlimit)
        {
            _mark = _in.Position;
        }

        public void Reset()
        {
            _in.Seek(_mark, SeekOrigin.Begin);
        }

        public bool MarkSupported()
        {
            return true;
        }

        public Stream AsStream()
        {
            return _in;
        }
    }
}
