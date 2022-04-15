using System.IO;

namespace SigningServer.Android.IO
{
    public class ByteArrayOutputStream : OutputStream
    {
        private MemoryStream mOut;
        
        public ByteArrayOutputStream()
        {
            mOut = new MemoryStream();
        }
        
        public ByteArrayOutputStream(int capacity)
        {
            mOut = new MemoryStream(capacity);
        }

        public sbyte[] ToByteArray()
        {
            return mOut.ToArray().AsSBytes();
        }

        public int Size()
        {
            return (int)mOut.Length;
        }

        public void Write(sbyte[] bytes)
        {
            Write(bytes, 0, bytes.Length);
        }

        public void Write(sbyte[] bytes, int offset, int length)
        {
            mOut.Write(bytes.AsBytes(), offset, length);
        }

        public void Dispose()
        {
            mOut.Dispose();
        }

        public void Write(int c)
        {
            mOut.WriteByte((byte)c);
        }
    }
}