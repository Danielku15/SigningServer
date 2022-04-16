using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public class TreeMap<TKey, TValue> : DictionaryMap<TKey, TValue>, SortedMap<TKey, TValue>
    {
        public TreeMap() : base(new SortedDictionary<TKey, TValue>())
        {
        }
    }
}