using System;
using System.IO;

namespace SigningServer.Android.IO
{
    public class InputStream : IDisposable
    {
    }

    public class FileInputStream : InputStream
    {
        public FileInputStream(FileInfo info)
        {
            throw new NotImplementedException();
        }
    }
}