using System.Runtime.CompilerServices;

namespace SigningServer.Android.Core
{
    public static class CharExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsWhitespace(char c)
        {
            return char.IsWhiteSpace(c);
        }
    }
}