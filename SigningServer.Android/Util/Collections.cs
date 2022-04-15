using System;
using System.Collections.Generic;
using SigningServer.Android.Collections;

namespace SigningServer.Android.Util
{
    public static class Collections
    {
        public static void Sort<T>(Android.Collections.List<T> fields, Comparison<T> func)
        {
            fields.Sort(func);
        }

        public static void Sort<T>(Android.Collections.List<T> fields, IComparer<T> func)
        {
            fields.Sort(func);
        }

        public static void Sort<T>(Android.Collections.List<T> fields)
        {
            fields.Sort();
        }

        public static Android.Collections.List<T> SingletonList<T>(T item)
        {
            return new Android.Collections.List<T>
            {
                item
            };
        }

        public static Android.Collections.List<T> EmptyList<T>()
        {
            return new Android.Collections.List<T>();
        }

        public static Set<T> EmptySet<T>()
        {
            return new Android.Collections.HashSet<T>();
        }

        public static Map<TKey, TValue> EmptyMap<TKey, TValue>()
        {
            return new HashMap<TKey, TValue>();
        }

        public static Android.Collections.List<T> UnmodifiableList<T>(Android.Collections.List<T> list)
        {
            return list;
        }
    }
}