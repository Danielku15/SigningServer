using System;
using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public class EnumMap<TKey, TValue> : Dictionary<TKey, TValue>,  Map<TKey, TValue>
    {
        public EnumMap(Type enumType)
        {
        }
        
    }
}