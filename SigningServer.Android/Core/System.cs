using System;
using SigningServer.Android.IO;

namespace SigningServer.Android.Core
{
    public class System
    {
        public static readonly PrintStream output = new PrintStream(Console.Out);

        public static void Arraycopy(Array src, int srcIndex, Array dest, int destIndex, int length)
        {
            Array.Copy(src, srcIndex, dest, destIndex, length);
        }
    }
}