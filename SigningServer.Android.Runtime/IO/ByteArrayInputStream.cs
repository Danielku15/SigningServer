using System.IO;

namespace SigningServer.Android.IO
{
    internal class ByteArrayInputStream : InputStream
    {
        private MemoryStream mIn;
        private long mMark = 0;

        public ByteArrayInputStream(byte[] source)
        {
            mIn = new MemoryStream(source);
        }

        public void Dispose()
        {
            mIn.Dispose();
        }

        public int Read(byte[] buffer, int offset, int len)
        {
            var count = mIn.Read(buffer, offset, len);
            return count == 0 ? -1 : count;
        }

        public int Read()
        {
            return mIn.ReadByte();
        }

        public int Read(byte[] b)
        {
            return Read(b, 0, b.Length);
        }

        public long Skip(long n)
        {
            var pos = mIn.Position;
            var newPos = mIn.Seek(n, SeekOrigin.Current);
            return newPos - pos;
        }

        public int Available()
        {
            return (int)(mIn.Length - mIn.Position);
        }

        public void Mark(int readlimit)
        {
            mMark = mIn.Position;
        }

        public void Reset()
        {
            mIn.Seek(mMark, SeekOrigin.Begin);
        }

        public bool MarkSupported()
        {
            return true;
        }

        public Stream AsStream()
        {
            return mIn;
        }
    }
}