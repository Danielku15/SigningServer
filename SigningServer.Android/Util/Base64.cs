using System;

namespace SigningServer.Android.Util
{
    public static class Base64
    {
        public class Encoder
        {
            public string EncodeToString(sbyte[] entryDigest)
            {
                var unsigned = (byte[])(object)entryDigest;
                return Convert.ToBase64String(unsigned);
            }
        }

        public class Decoder
        {
            public sbyte[] Decode(string digestBase64)
            {
                var unsigned = Convert.FromBase64String(digestBase64);
                return (sbyte[])(object)unsigned;
            }
        }

        private static readonly Encoder ENCODER = new Encoder();
        private static readonly Decoder DECODER = new Decoder();

        public static Encoder GetEncoder()
        {
            return ENCODER;
        }

        public static Decoder GetDecoder()
        {
            return DECODER;
        }
    }
}