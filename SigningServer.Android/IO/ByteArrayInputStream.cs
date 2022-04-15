using System.IO;

namespace SigningServer.Android.IO
{
    public class ByteArrayInputStream : InputStream
    {
        private MemoryStream mIn;
        private long mMark = 0;

        public ByteArrayInputStream(sbyte[] source)
        {
            mIn = new MemoryStream(source.AsBytes());
        }

        public void Dispose()
        {
            mIn.Dispose();
        }

        public int Read(sbyte[] buffer, int offset, int len)
        {
            var count = mIn.Read(buffer.AsBytes(), offset, len);
            return count == 0 ? -1 : count;
        }

        public int Read()
        {
            return mIn.ReadByte();
        }

        public int Read(sbyte[] b)
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