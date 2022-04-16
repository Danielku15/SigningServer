using System;
using System.Collections.Generic;
using System.Linq;
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
        public static int GetHashCode(byte[] a)
        {
            if (a == null)
                return 0;

            int result = 1;
            foreach (byte element in a)
            {
                result = 31 * result + element;
            }

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetHashCode(object[] a)
        {
            if (a == null)
                return 0;

            int result = 1;
            foreach (var element in a)
            {
                result = 31 * result + (element?.GetHashCode() ?? 0);
            }

            return result;
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