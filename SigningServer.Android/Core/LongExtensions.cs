using System;
using System.Runtime.CompilerServices;

namespace SigningServer.Android.Core
{
    public static class BoolExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToString(bool value)
        {
            return value.ToString();
        }
    }

    public static class IntExtensions
    {
        public const int MaxValue = int.MaxValue;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToString(int value)
        {
            return value.ToString();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToHexString(int value)
        {
            return value.ToString("x");
        }

        public static int ParseInt(string s)
        {
            return int.Parse(s);
        }
    }

    public static class SByteExtensions
    {
        public static int SIZE;
    }

    public static class LongExtensions
    {
        public static int SIZE;
        public static long MAX_VALUE;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToHexString(long value)
        {
            return value.ToString("x");
        }

        public static long ParseLong(string s)
        {
            throw new NotImplementedException();
        }
    }
}