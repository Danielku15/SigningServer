using System.IO;

namespace SigningServer.Android.IO
{
    internal class FileInputStream : WrapperInputStream
    {
        public FileInputStream(FileInfo info)
        : base(info.Open(FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
        }
    }
}