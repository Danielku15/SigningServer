using System;
using System.IO;

namespace SigningServer.Android.IO
{
    public class InputStream : IDisposable
    {
        public virtual int Read(sbyte[] buffer, int i, int len)
        {
            throw new NotImplementedException();
        }

        public virtual int Read()
        {
            throw new NotImplementedException();
        }

        public int Skip(int len)
        {
            throw new NotImplementedException();
        }

        public virtual int Read(sbyte[] b)
        {
            throw new NotImplementedException();
        }

        public virtual long Skip(long n)
        {
            throw new NotImplementedException();
        }

        public virtual int Available()
        {
            throw new NotImplementedException();
        }

        public virtual void Dispose()
        {
            throw new NotImplementedException();
        }

        public virtual void Mark(int readlimit)
        {
            throw new NotImplementedException();
        }

        public virtual void Reset()
        {
            throw new NotImplementedException();
        }

        public virtual bool MarkSupported()
        {
            throw new NotImplementedException();
        }
    }

    public class FileInputStream : InputStream
    {
        public FileInputStream(FileInfo info)
        {
            throw new NotImplementedException();
        }
    }
}