using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace SigningServer.Android.Collections
{
    public class DictionaryMap<TKey, TValue> : Map<TKey, TValue>
    {
        private readonly IDictionary<TKey, TValue> mDictionary;
        
        public DictionaryMap()
        {
            mDictionary = new Dictionary<TKey, TValue>();
        }

        public TValue this[TKey index]
        {
            get => mDictionary[index];
            set => mDictionary[index] = value;
        }
        
        public int Size()
        {
            return mDictionary.Count;
        }

        protected DictionaryMap(IDictionary<TKey, TValue> storage)
        {
            mDictionary = storage;
        }

        public DictionaryMap(int capacity)
        {
            mDictionary = new Dictionary<TKey, TValue>(capacity);
        }

        public void Clear()
        {
            mDictionary.Clear();
        }

        public bool ContainsKey(TKey key)
        {
            return mDictionary.ContainsKey(key);
        }

        public bool Remove(TKey key)
        {
            return mDictionary.Remove(key);
        }

        public TValue Get(TKey key)
        {
            mDictionary.TryGetValue(key, out var v);
            return v;
        }

        public TValue Put(TKey key, TValue value)
        {
            mDictionary.TryGetValue(key, out var v);
            mDictionary[key] = value;
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
                return mDictionaryMap.mDictionary.Select(kvp => new MapEntry<TKey, TValue>(kvp)).GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }

            public bool Add(MapEntry<TKey, TValue> value)
            {
                throw new InvalidOperationException();
            }

            public bool Remove(MapEntry<TKey, TValue> value)
            {
                throw new InvalidOperationException();
            }

            public bool IsEmpty()
            {
                return mDictionaryMap.IsEmpty();
            }

            public bool Contains(MapEntry<TKey, TValue> value)
            {
                return mDictionaryMap.mDictionary.TryGetValue(value.GetKey(), out var v) && v.Equals(value);
            }

            public bool ContainsAll(Collection<MapEntry<TKey, TValue>> other)
            {
                return other.All(Contains);
            }

            public MapEntry<TKey, TValue>[] ToArray(MapEntry<TKey, TValue>[] empty)
            {
                return mDictionaryMap.mDictionary.Select(kvp => new MapEntry<TKey, TValue>(kvp)).ToArray();
            }

            public int Size()
            {
                return mDictionaryMap.mDictionary.Count;
            }


            public override bool Equals(object obj)
            {
                if (ReferenceEquals(this, obj))
                {
                    return true;
                }

                if (obj == null)
                {
                    return false;
                }

                return GetHashCode() == obj.GetHashCode();
            }

            public override int GetHashCode()
            {
                var hashCode = 1;
                foreach (var item in this)
                {
                    hashCode = 31 * hashCode + item.GetHashCode();
                }

                return hashCode;
            }
        }

        public IEnumerable<TValue> Values()
        {
            return mDictionary.Values;
        }

        public bool IsEmpty()
        {
            return mDictionary.Count == 0;
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
                return mDictionaryMap.mDictionary.Keys.GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }

            public bool Add(TKey value)
            {
                throw new InvalidOperationException();
            }

            public bool Remove(TKey value)
            {
                throw new InvalidOperationException();
            }

            public bool IsEmpty()
            {
                return mDictionaryMap.IsEmpty();
            }

            public bool Contains(TKey value)
            {
                return mDictionaryMap.mDictionary.ContainsKey(value);
            }

            public bool ContainsAll(Collection<TKey> other)
            {
                return other.All(Contains);
            }

            public TKey[] ToArray(TKey[] empty)
            {
                return mDictionaryMap.mDictionary.Keys.ToArray();
            }

            public int Size()
            {
                return mDictionaryMap.mDictionary.Count;
            }


            public override bool Equals(object obj)
            {
                if (ReferenceEquals(this, obj))
                {
                    return true;
                }

                if (obj == null)
                {
                    return false;
                }

                return GetHashCode() == obj.GetHashCode();
            }

            public override int GetHashCode()
            {
                var hashCode = 1;
                foreach (var item in this)
                {
                    hashCode = 31 * hashCode + item.GetHashCode();
                }

                return hashCode;
            }
        }
    }
}