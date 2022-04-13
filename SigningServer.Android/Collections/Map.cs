using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public interface Map<TKey, TValue>
    {
        TValue Get(TKey key);
        void Put(TKey key, TValue value);
        Set<MapEntry<TKey, TValue>> EntrySet();
        bool ContainsKey(TKey key);
        IEnumerable<TValue> Values();
        bool IsEmpty();
        Set<TKey> KeySet();
    }
}