using System.IO;
using System.Text;

namespace SigningServer.Server.SigningTool
{
    public static class ManifestStreamWriterExtensions
    {
        public static byte[] WriteManifestLine(this Stream writer, string line)
        {
            var singleByteString = new StringBuilder(Encoding.Default.GetString(Encoding.UTF8.GetBytes(line + "\r\n")));
            var length = singleByteString.Length;
            if (length > 72)
            {
                int index = 70;
                while (index < (length - 2))
                {
                    singleByteString.Insert(index, "\r\n ");
                    index += 72;
                    length += 3;
                }
            }

            var result = Encoding.Default.GetBytes(singleByteString.ToString());
            writer.Write(result, 0, result.Length);
            return result;
        }
    }
}