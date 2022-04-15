using System.IO;

namespace SigningServer.Android.IO
{
    public class WrapperInputStream : InputStream
    {
        private readonly Stream mIn;

        public WrapperInputStream(Stream @in)
        {
            mIn = @in;
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
            return mIn;
        }
    }
}