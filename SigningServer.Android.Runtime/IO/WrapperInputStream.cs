using System.IO;

namespace SigningServer.Android.IO
{
    internal class WrapperInputStream : InputStream
    {
        private readonly Stream _in;

        public WrapperInputStream(Stream @in)
        {
            _in = @in;
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
        }

        public void Reset()
        {
            throw new IOException("mark/reset not supported");
        }

        public bool MarkSupported()
        {
            return false;
        }

        public Stream AsStream()
        {
            return _in;
        }
    }
}
