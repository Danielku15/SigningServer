using System.Runtime.CompilerServices;
using SigningServer.Android.Collections;

namespace SigningServer.Android.Util
{
    public class Objects
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int Hash(params object[] objs)
        {
            return Arrays.GetHashCode(objs);
        }
    }
}