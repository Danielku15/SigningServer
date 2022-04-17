using System.Runtime.CompilerServices;

namespace SigningServer.Android.Core
{
    internal static class System
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Arraycopy(byte[] src, int srcIndex, byte[] dest, int destIndex, int length)
        {
            global::System.Buffer.BlockCopy(src, srcIndex, dest, destIndex, length);
        }
    }
}