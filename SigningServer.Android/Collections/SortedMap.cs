using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public interface SortedMap<TKey, TValue> : Map<TKey, TValue>
    {
        void Remove(TKey key);
    }
}