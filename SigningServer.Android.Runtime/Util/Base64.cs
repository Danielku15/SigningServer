using System;

namespace SigningServer.Android.Util
{
    internal static class Base64
    {
        public class Encoder
        {
            public string EncodeToString(byte[] entryDigest)
            {
                return Convert.ToBase64String(entryDigest);
            }
        }

        public class Decoder
        {
            public byte[] Decode(string digestBase64)
            {
                return Convert.FromBase64String(digestBase64);
            }
        }

        private static readonly Encoder EncoderInstance = new Encoder();
        private static readonly Decoder DecoderInstance = new Decoder();

        public static Encoder GetEncoder()
        {
            return EncoderInstance;
        }

        public static Decoder GetDecoder()
        {
            return DecoderInstance;
        }
    }
}
