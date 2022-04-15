using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;

namespace SigningServer.Android
{
    internal static class Extensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string SubstringIndex(this string s, int start)
        {
            return s.Substring(start);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string SubstringIndex(this string s, int start, int end)
        {
            return s.Substring(start, end - start);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string[] Split(this string s, string sep)
        {
            return s.Split(new[] { sep }, StringSplitOptions.None);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string GetName(this Type t)
        {
            return t.Name;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void PrintStackTrace(this Exception s)
        {
            Console.WriteLine(s.ToString());
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string GetMessage(this Exception s)
        {
            return s.Message;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsEmpty(this string s)
        {
            return s.Length == 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static char CharAt(this string s, int i)
        {
            return s[i];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static sbyte[] GetBytes(this string s)
        {
            return Encoding.Default.GetBytes(s).AsSBytes();
        }

        public static sbyte[] GetBytes(this string s, Encoding encoding)
        {
            return encoding.GetBytes(s).AsSBytes();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static sbyte[] AsSBytes(this byte[] b)
        {
            // CLR allows conversion from sbyte to byte array
            return (sbyte[])(object)b;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] AsBytes(this sbyte[] b)
        {
            // CLR allows conversion from sbyte to byte array
            return (byte[])(object)b;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToUpperCase(this string s)
        {
            return s.ToUpper();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToUpperCase(this string s, CultureInfo cultureInfo)
        {
            return s.ToUpper(cultureInfo);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToLowerCase(this string s)
        {
            return s.ToLower();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ToLowerCase(this string s, CultureInfo cultureInfo)
        {
            return s.ToLower(cultureInfo);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool EqualsIgnoreCase(this string s, string other)
        {
            return s.Equals(other, StringComparison.OrdinalIgnoreCase);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int Length(this string s)
        {
            return s.Length;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsEmpty<T>(this ISet<T> set)
        {
            return set.Count == 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Put<TKey, TValue>(this IDictionary<TKey, TValue> map, TKey key, TValue value)
        {
            map[key] = value;
        }

        public static string ReplaceFirst(this string text, string search, string replace)
        {
            var pos = text.IndexOf(search, StringComparison.Ordinal);
            if (pos < 0)
            {
                return text;
            }

            return text.Substring(0, pos) + replace + text.Substring(pos + search.Length);
        }
    }
}