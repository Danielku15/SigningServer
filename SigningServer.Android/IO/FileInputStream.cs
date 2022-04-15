using System.IO;

namespace SigningServer.Android.IO
{
    public class FileInputStream : WrapperInputStream
    {
        public FileInputStream(FileInfo info)
        : base(info.Open(FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
        }
    }
}