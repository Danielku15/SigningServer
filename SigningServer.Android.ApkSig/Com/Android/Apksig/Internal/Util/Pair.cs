using System.Runtime.CompilerServices;

// ReSharper disable once CheckNamespace
namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    internal static class Pair
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Pair<A, B> Of<A, B>(A a, B b)
        {
            return Pair<A, B>.Of(a, b);
        }
    }
}
