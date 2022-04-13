using System;

namespace SigningServer.Android.Util
{
    public class Base64
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