using System;
using System.Numerics;
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
        public static int bitLength (this BigInteger v)
        {
            // https://github.com/dotnet/runtime/blob/v6.0.3/src/libraries/System.Runtime.Numerics/src/System/Numerics/BigInteger.cs#L2406
            byte highValue;
            int bitsArrayLength;
            int sign = v.Sign;
            var bits = v.ToByteArray();

            bitsArrayLength = bits.Length;
            highValue = bits[bitsArrayLength - 1];

            int bitLength = bitsArrayLength * 8 - LeadingZeroCount(highValue);

            if (sign >= 0)
                return bitLength;

            // When negative and IsPowerOfTwo, the answer is (bitLength - 1)

            // Check highValue
            if ((highValue & (highValue - 1)) != 0)
            {
                return bitLength;
            }

            // Check the rest of the bits (if present)
            for (int i = bitsArrayLength - 2; i >= 0; i--)
            {
                // bits array is always non-null when bitsArrayLength >= 2
                if (bits[i] == 0)
                {
                    continue;
                }

                return bitLength;
            }

            return bitLength - 1;
        }

        private static int LeadingZeroCount(byte x)
        {
            if (x == 0)
            {
                return 8;
            }

            return LeadingZeroCount((int)x) - (3 * 8) /* Remove first 3 byets */;
        }
        
        private static int LeadingZeroCount(int x)
        {
            if (x == 0)
            {
                return 8;
            }
            
            const int numIntBits = sizeof(int) * 8; //compile time constant
            //do the smearing
            x |= x >> 1; 
            x |= x >> 2;
            x |= x >> 4;
            x |= x >> 8;
            x |= x >> 16;
            //count the ones
            x -= x >> 1 & 0x55555555;
            x = (x >> 2 & 0x33333333) + (x & 0x33333333);
            x = (x >> 4) + x & 0x0f0f0f0f;
            x += x >> 8;
            x += x >> 16;
            return numIntBits - (x & 0x0000003f); //subtract # of 1s from 32
        }
    }
}