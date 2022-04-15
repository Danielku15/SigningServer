using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace SigningServer.Android.Collections
{
    public static class Arrays
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static List<T> AsList<T>(params T[] items)
        {
            return new List<T>(items);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int BinarySearch<T>(T[] array, T value, IComparer<T> comparer)
        {
            return Array.BinarySearch(array, value, comparer);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetHashCode<T>(T[] array)
        {
        }

        public static sbyte[] CopyOfRange(sbyte[] manifest, int startOffset, int newlineStartOffset)
        {
            throw new NotImplementedException();
        }

        public static sbyte[] CopyOf(sbyte[] array, int newSize)
        {
            throw new NotImplementedException();
        }
    }
}