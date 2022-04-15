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
        public static int GetHashCode(sbyte[] a)
        {
            if (a == null)
                return 0;

            int result = 1;
            foreach (sbyte element in a)
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

        public static sbyte[] CopyOfRange(sbyte[] original, int from, int to)
        {
            var length = to - from;
            if (length < 0)
            {
                throw new ArgumentException(from + " > " + to);
            }

            var copy = new sbyte[length];
            Array.Copy(original, from, copy, 0, System.Math.Min(original.Length - from, length));
            return copy;
        }

        public static sbyte[] CopyOf(sbyte[] original, int newSize)
        {
            var copy = new sbyte[newSize];
            Array.Copy(original, 0, copy, 0, System.Math.Min(original.Length, newSize));
            return copy;
        }
    }
}