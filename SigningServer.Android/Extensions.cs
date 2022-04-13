using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace SigningServer.Android
{
    internal static class Extensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string[] Split(this string s, string sep)
        {
            return s.Split(new[] { sep }, StringSplitOptions.None);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string GetName(this System.Type t)
        {
            return t.Name;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void PrintStackTrace(this Exception s)
        {
            Console.WriteLine(s.ToString());
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string GetMessage(this Exception s)
        {
            return s.Message;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsEmpty(this string s)
        {
            return s.Length == 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static char CharAt(this string s, int i)
        {
            return s[i];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static sbyte[] GetBytes(this string s, Encoding encoding)
        {
            return encoding.GetBytes(s).ToSBytes();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static sbyte[] ToSBytes(this byte[] b)
        {
            var s = new sbyte[b.Length];
            Buffer.BlockCopy(b, 0, s, 0, s.Length);
            return s;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToUpperCase(this string s)
        {
            return s.ToUpper();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToUpperCase(this string s, CultureInfo cultureInfo)
        {
            return s.ToUpper(cultureInfo);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToLowerCase(this string s)
        {
            return s.ToLower();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToLowerCase(this string s, CultureInfo cultureInfo)
        {
            return s.ToLower(cultureInfo);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool EqualsIgnoreCase(this string s, string other)
        {
            return s.Equals(other, StringComparison.OrdinalIgnoreCase);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int Length(this string s)
        {
            return s.Length;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsEmpty<T>(this ISet<T> set)
        {
            return set.Count == 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Put<TKey, TValue>(this IDictionary<TKey, TValue> map, TKey key, TValue value)
        {
            map[key] = value;
        }

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
            var data = new byte[buf.Remaining()];
            buf.Get(data);
            hashAlgorithm.TransformBlock(data, 0, data.Length, null, 0);
        }

        public static void TransformFinalBlock(this HashAlgorithm hashAlgorithm, ByteBuffer buf)
        {
            // TODO: check for correctness
            var data = new byte[buf.Remaining()];
            buf.Get(data);
            hashAlgorithm.TransformFinalBlock(data, 0, data.Length);
        }

        public static int bitLength(this BigInteger v)
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