using System;
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

        public byte[] ToByteArray()
        {
            return mOut.ToArray();
        }

        public int Size()
        {
            return (int)mOut.Length;
        }

        public void Write(byte[] bytes)
        {
            Write(bytes, 0, bytes.Length);
        }

        public void Write(byte[] bytes, int offset, int length)
        {
            if (offset < 0 || offset + length > bytes.Length)
            {
                throw new IndexOutOfRangeException();
            }
            mOut.Write(bytes, offset, length);
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