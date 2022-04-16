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

        public bool Equals(MapEntry<TKey, TValue> other)
        {
            return EqualityComparer<TKey>.Default.Equals(mKvp.Key, other.mKvp.Key) &&
                   EqualityComparer<TValue>.Default.Equals(mKvp.Value, other.mKvp.Value);
        }

        public override bool Equals(object obj)
        {
            return obj is MapEntry<TKey, TValue> other && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (EqualityComparer<TKey>.Default.GetHashCode(mKvp.Key) * 397) ^
                       EqualityComparer<TValue>.Default.GetHashCode(mKvp.Value);
            }
        }
    }
}