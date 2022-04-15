using System;
using System.IO;

namespace SigningServer.Android.IO
{
    public interface InputStream : IDisposable
    {
        int Read(sbyte[] buffer, int offset, int len);
        int Read();
        int Read(sbyte[] b);
        long Skip(long n);
        int Available();
        void Mark(int readlimit);
        void Reset();
        bool MarkSupported();
        Stream AsStream();
    }
}