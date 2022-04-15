using System.IO;

namespace SigningServer.Android.IO
{
    public class FileOutputStream : OutputStream
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
        
        public void Write(sbyte[] bytes)
        {
            Write(bytes, 0, bytes.Length);
        }

        public void Write(sbyte[] bytes, int offset, int length)
        {
            mFileStream.Write(bytes.AsBytes(), offset, length);
        }
    }
}