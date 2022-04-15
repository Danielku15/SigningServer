using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public struct MapEntry<TKey, TValue>
    {
        private KeyValuePair<TKey, TValue> mKvp;

        public MapEntry(KeyValuePair<TKey, TValue> kvp)
        {
            mKvp = kvp;
        }

        public TKey GetKey()
        {
            return mKvp.Key;
        }

        public TValue GetValue()
        {
            return mKvp.Value;
        }
    }
}