using System.IO;

namespace SigningServer.Android.IO.Channels
{
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
            var x = new sbyte[rem];
            var actual = mStream.Read(x.AsBytes(), 0, rem);

            buf.Put(x, 0, actual);
            return actual;
        }

        public void Write(ByteBuffer buf)
        {
            var x = new sbyte[buf.Remaining()];
            buf.Get(x);
            mStream.Write(x.AsBytes(), 0, x.Length);
        }
    }
}