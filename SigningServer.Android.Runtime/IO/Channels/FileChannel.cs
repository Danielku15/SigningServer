using System.IO;

namespace SigningServer.Android.IO.Channels
{
    public class FileChannel
    {
        private readonly FileStream _stream;

        public FileChannel(FileStream stream)
        {
            _stream = stream;
        }

        public long Size()
        {
            return _stream.Length;
        }

        public void Position(long position)
        {
            _stream.Seek(position, SeekOrigin.Begin);
        }

        public int Read(ByteBuffer buf)
        {
            var rem = buf.Remaining();
            var x = new byte[rem];
            var actual = _stream.Read(x, 0, rem);

            buf.Put(x, 0, actual);
            return actual;
        }

        public void Write(ByteBuffer buf)
        {
            var x = new byte[buf.Remaining()];
            buf.Get(x);
            _stream.Write(x, 0, x.Length);
        }
    }
}
