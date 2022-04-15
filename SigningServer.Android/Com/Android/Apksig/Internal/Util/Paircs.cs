using System.Runtime.CompilerServices;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    public static class Pair
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Pair<A, B> Of<A, B>(A a, B b)
        {
            return Pair<A, B>.Of(a, b);
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Pair<int?, int?> Of(int a, int b)
        {
            return Pair<int?, int?>.Of<int?, int?>(a, b);
        }
        
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Pair<int?, long?> Of(int a, long b)
        {
            return Pair<int?, long?>.Of<int?, long?>(a, b);
        }
    }
}