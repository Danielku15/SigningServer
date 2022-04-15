using System;
using System.Runtime.CompilerServices;

namespace SigningServer.Android.Core
{
    public static class IntExtensions
    {
        public const int MIN_VALUE = int.MinValue;
        public const int MAX_VALUE = int.MaxValue;

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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ParseInt(string s)
        {
            try
            {
                return int.Parse(s);
            }
            catch (FormatException e)
            {
                throw new NumberFormatException(e.Message, e);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ValueOf(int v)
        {
            return v;
        }
    }
}