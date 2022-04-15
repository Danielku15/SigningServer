using System;
using System.Runtime.CompilerServices;
using SigningServer.Android.IO;

namespace SigningServer.Android.Core
{
    public static class System
    {
        public static readonly PrintStream output = new PrintStream(Console.Out);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Arraycopy(Array src, int srcIndex, Array dest, int destIndex, int length)
        {
            Array.Copy(src, srcIndex, dest, destIndex, length);
        }
    }
}