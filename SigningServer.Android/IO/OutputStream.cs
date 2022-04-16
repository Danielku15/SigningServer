using System;

namespace SigningServer.Android.IO
{
    public interface OutputStream : IDisposable
    {
        public void Write(int b);
        public void Write(byte[] bytes);
        public void Write(byte[] bytes, int offset, int length);
    }
}