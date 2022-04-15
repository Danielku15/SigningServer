using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace SigningServer.Android.Collections
{
    public class DictionaryMap<TKey, TValue> : Dictionary<TKey, TValue>, Map<TKey, TValue>
    {
        public DictionaryMap()
        {
        }

        public DictionaryMap(int capacity) : base(capacity)
        {
        }

        public TValue Get(TKey key)
        {
            TryGetValue(key, out var v);
            return v;
        }

        public TValue Put(TKey key, TValue value)
        {
            TryGetValue(key, out var v);
            this[key] = value;
            return v;
        }

        public Set<MapEntry<TKey, TValue>> EntrySet()
        {
            return new EntrySetImpl(this);
        }

        private class EntrySetImpl : Set<MapEntry<TKey, TValue>>
        {
            private readonly DictionaryMap<TKey, TValue> mDictionaryMap;

            public EntrySetImpl(DictionaryMap<TKey, TValue> dictionaryMap)
            {
                mDictionaryMap = dictionaryMap;
            }

            public IEnumerator<MapEntry<TKey, TValue>> GetEnumerator()
            {
                return mDictionaryMap.Select(kvp => new MapEntry<TKey, TValue>(kvp)).GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }

            public bool Add(MapEntry<TKey, TValue> value)
            {
                throw new InvalidOperationException();
            }

            public bool IsEmpty()
            {
                return mDictionaryMap.IsEmpty();
            }

            public bool Contains(MapEntry<TKey, TValue> value)
            {
                return mDictionaryMap.TryGetValue(value.GetKey(), out var v) && v.Equals(value);
            }

            public MapEntry<TKey, TValue>[] ToArray(MapEntry<TKey, TValue>[] empty)
            {
                return mDictionaryMap.Select(kvp => new MapEntry<TKey, TValue>(kvp)).ToArray();
            }

            public int Size()
            {
                return mDictionaryMap.Count;
            }
        }

        public new IEnumerable<TValue> Values()
        {
            return base.Values;
        }

        public bool IsEmpty()
        {
            return Count == 0;
        }

        public Set<TKey> KeySet()
        {
            return new KeySetImpl(this);
        }

        private class KeySetImpl : Set<TKey>
        {
            private readonly DictionaryMap<TKey, TValue> mDictionaryMap;

            public KeySetImpl(DictionaryMap<TKey, TValue> dictionaryMap)
            {
                mDictionaryMap = dictionaryMap;
            }

            public IEnumerator<TKey> GetEnumerator()
            {
                return mDictionaryMap.Keys.GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }

            public bool Add(TKey value)
            {
                throw new InvalidOperationException();
            }

            public bool IsEmpty()
            {
                return mDictionaryMap.IsEmpty();
            }

            public bool Contains(TKey value)
            {
                return mDictionaryMap.ContainsKey(value);
            }

            public TKey[] ToArray(TKey[] empty)
            {
                return mDictionaryMap.Keys.ToArray();
            }

            public int Size()
            {
                return mDictionaryMap.Count;
            }
        }
    }
}