using System.IO;

namespace SigningServer.Android.IO
{
    internal class FileOutputStream : OutputStream
    {
        private readonly FileStream _fileStream;

        public FileOutputStream(FileInfo file)
        {
            _fileStream = file.Open(FileMode.Create, FileAccess.ReadWrite, FileShare.Read);
        }

        public void Dispose()
        {
            _fileStream.Dispose();
        }

        public void Write(int b)
        {
            _fileStream.WriteByte((byte)b);
        }
        
        public void Write(byte[] bytes)
        {
            Write(bytes, 0, bytes.Length);
        }

        public void Write(byte[] bytes, int offset, int length)
        {
            _fileStream.Write(bytes, offset, length);
        }
    }
}
