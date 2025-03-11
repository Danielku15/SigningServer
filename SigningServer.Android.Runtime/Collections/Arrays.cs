using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

namespace SigningServer.Android.Collections
{
    internal static class Arrays
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
        public static int GetHashCode(byte[] a)
        {
            return a == null ? 0 : a.Aggregate(1, (current, element) => 31 * current + element);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetHashCode(object[] a)
        {
            return a == null ? 0 : a.Aggregate(1, (current, element) => 31 * current + (element?.GetHashCode() ?? 0));
        }

        public static byte[] CopyOfRange(byte[] original, int from, int to)
        {
            var length = to - from;
            if (length < 0)
            {
                throw new ArgumentException(from + " > " + to);
            }

            var copy = new byte[length];
            Buffer.BlockCopy(original, from, copy, 0, System.Math.Min(original.Length - from, length));
            return copy;
        }

        public static byte[] CopyOf(byte[] original, int newSize)
        {
            var copy = new byte[newSize];
            Buffer.BlockCopy(original, 0, copy, 0, System.Math.Min(original.Length, newSize));
            return copy;
        }

        public static bool Equals<T>(T[] a, T[] b)
        {
            return a.SequenceEqual(b);
        }
    }
}