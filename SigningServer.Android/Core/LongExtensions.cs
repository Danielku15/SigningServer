using System;
using System.Runtime.CompilerServices;

namespace SigningServer.Android.Core
{
    public static class LongExtensions
    {
        public const int SIZE = 64;
        public const long MAX_VALUE = long.MaxValue;
        public const long MIN_VALUE = long.MinValue;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToHexString(long value)
        {
            return value.ToString("x");
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long ParseLong(string s)
        {
            try
            {
                return long.Parse(s);
            }
            catch (FormatException e)
            {
                throw new NumberFormatException(e.Message, e);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long ValueOf(long v)
        {
            return v;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToString(long v)
        {
            return v.ToString();
        }
    }
}