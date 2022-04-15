using System;
using System.Runtime.CompilerServices;

namespace SigningServer.Android.Core
{
    public static class IntExtensions
    {
        public static int MIN_VALUE;
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

        public static int ValueOf(int integerToInt)
        {
            throw new NotImplementedException();
        }
    }
}