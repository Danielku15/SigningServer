using System.IO;

namespace SigningServer.Android.Util
{
    static class StreamUtils
    {
        public static long Remaining(this Stream stream)
        {
            return stream.Length - stream.Position;
        }
    }
}
