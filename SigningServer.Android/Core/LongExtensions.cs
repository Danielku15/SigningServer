using System;
using System.Runtime.CompilerServices;

namespace SigningServer.Android.Core
{
    public static class LongExtensions
    {
        public static int SIZE;
        public static long MAX_VALUE;
        public static long MIN_VALUE;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToHexString(long value)
        {
            return value.ToString("x");
        }

        public static long ParseLong(string s)
        {
            throw new NotImplementedException();
        }

        public static long ValueOf(long integerToLong)
        {
            throw new NotImplementedException();
        }

        public static string ToString(long v)
        {
            
        }
    }
}