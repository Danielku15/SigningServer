using System;
using System.Runtime.CompilerServices;
using SigningServer.Android.IO;

namespace SigningServer.Android.Core
{
    public static class System
    {
        public static readonly PrintStream output = new PrintStream(Console.Out);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Arraycopy(byte[] src, int srcIndex, byte[] dest, int destIndex, int length)
        {
            global::System.Buffer.BlockCopy(src, srcIndex, dest, destIndex, length);
        }
    }
}