using System;

namespace SigningServer.Android.IO
{
    public interface OutputStream : IDisposable
    {
        public void Write(int b);
        public void Write(sbyte[] bytes);
        public void Write(sbyte[] bytes, int offset, int length);
    }
}