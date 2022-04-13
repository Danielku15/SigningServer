using System;
using SigningServer.Android.Collections;
using SigningServer.Android.Com.Android.Apksig.Internal.Asn1;
using SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7;

namespace SigningServer.Android.Util
{
    public class Collections
    {
        public static void Sort<T>(List<T> fields, Comparison<T> func)
        {
            fields.Sort(func);
        }

        public static void Sort<T>(List<T> fields)
        {
            fields.Sort();
        }

        public static List<T> SingletonList<T>(T item)
        {
            return new List<T>
            {
                item
            };
        }

        public static List<T> EmptyList<T>()
        {
            return new List<T>();
        }
    }
}