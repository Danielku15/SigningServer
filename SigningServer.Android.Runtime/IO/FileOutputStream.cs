using System.IO;

namespace SigningServer.Android.IO
{
    internal class FileOutputStream : OutputStream
    {
        private readonly FileStream mFileStream;

        public FileOutputStream(FileInfo file)
        {
            mFileStream = file.Open(FileMode.Create, FileAccess.ReadWrite, FileShare.Read);
        }

        public void Dispose()
        {
            mFileStream.Dispose();
        }

        public void Write(int b)
        {
            mFileStream.WriteByte((byte)b);
        }
        
        public void Write(byte[] bytes)
        {
            Write(bytes, 0, bytes.Length);
        }

        public void Write(byte[] bytes, int offset, int length)
        {
            mFileStream.Write(bytes, offset, length);
        }
    }
}