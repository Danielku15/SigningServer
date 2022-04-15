using System.Runtime.CompilerServices;

namespace SigningServer.Android
{
    public class TypeUtils
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int UnsignedRightShift(int a, int b)
        {
            return (int)((uint)a >> b);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long UnsignedRightShift(long a, int b)
        {
            return (long)((ulong)a >> b);
        }
    }
}