using System;
using System.Security.Cryptography;

namespace SigningServer.Android
{
    internal static class Extensions
    {
        public static string ReplaceFirst(this string text, string search, string replace)
        {
            var pos = text.IndexOf(search, StringComparison.Ordinal);
            if (pos < 0)
            {
                return text;
            }

            return text.Substring(0, pos) + replace + text.Substring(pos + search.Length);
        }

        public static void TransformBlock(this HashAlgorithm hashAlgorithm, ByteBuffer buf)
        {
            // TODO: check for correctness
            var data = new byte[buf.remaining()];
            buf.get(data);
            hashAlgorithm.TransformBlock(data, 0, data.Length, null, 0);
        }


        public static void TransformFinalBlock(this HashAlgorithm hashAlgorithm, ByteBuffer buf)
        {
            // TODO: check for correctness
            var data = new byte[buf.remaining()];
            buf.get(data);
            hashAlgorithm.TransformFinalBlock(data, 0, data.Length);
        }
    }
}