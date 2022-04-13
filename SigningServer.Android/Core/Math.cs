using System.Runtime.CompilerServices;

namespace SigningServer.Android.Core
{
    public class Math
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int Max(int a, int b)
        {
            return global::System.Math.Max(a, b);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long Max(long a, long b)
        {
            return global::System.Math.Max(a, b);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int Min(int a, int b)
        {
            return global::System.Math.Min(a, b);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long Min(long a, long b)
        {
            return global::System.Math.Min(a, b);
        }

        public static int ToIntExact(long v)
        {
            return (int)v;
        }
    }
}