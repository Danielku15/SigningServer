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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool Create(bool result)
        {
            return result;
        }
    }
}