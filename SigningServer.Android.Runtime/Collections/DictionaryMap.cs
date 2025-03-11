using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace SigningServer.Android.Collections
{
    public class DictionaryMap<TKey, TValue> : Map<TKey, TValue>
    {
        private readonly IDictionary<TKey, TValue> _dictionary;
        
        public DictionaryMap()
        {
            _dictionary = new Dictionary<TKey, TValue>();
        }

        public TValue this[TKey index]
        {
            get => _dictionary[index];
            set => _dictionary[index] = value;
        }
        
        public int Size()
        {
            return _dictionary.Count;
        }

        protected DictionaryMap(IDictionary<TKey, TValue> storage)
        {
            _dictionary = storage;
        }

        public DictionaryMap(int capacity)
        {
            _dictionary = new Dictionary<TKey, TValue>(capacity);
        }

        public void Clear()
        {
            _dictionary.Clear();
        }

        public bool ContainsKey(TKey key)
        {
            return _dictionary.ContainsKey(key);
        }

        public void Remove(TKey key)
        {
            _dictionary.Remove(key);
        }

        public TValue Get(TKey key)
        {
            _dictionary.TryGetValue(key, out var v);
            return v;
        }

        public TValue Put(TKey key, TValue value)
        {
            _dictionary.TryGetValue(key, out var v);
            _dictionary[key] = value;
            return v;
        }

        public Set<MapEntry<TKey, TValue>> EntrySet()
        {
            return new EntrySetImpl(this);
        }

        private class EntrySetImpl : Set<MapEntry<TKey, TValue>>
        {
            private readonly DictionaryMap<TKey, TValue> _dictionaryMap;

            public EntrySetImpl(DictionaryMap<TKey, TValue> dictionaryMap)
            {
                _dictionaryMap = dictionaryMap;
            }

            public IEnumerator<MapEntry<TKey, TValue>> GetEnumerator()
            {
                return _dictionaryMap._dictionary.Select(kvp => new MapEntry<TKey, TValue>(kvp)).GetEnumerator();
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
                return _dictionaryMap.IsEmpty();
            }

            public bool Contains(MapEntry<TKey, TValue> value)
            {
                return _dictionaryMap._dictionary.TryGetValue(value.GetKey(), out var v) && v.Equals(value);
            }

            public bool ContainsAll(Collection<MapEntry<TKey, TValue>> other)
            {
                return other.All(Contains);
            }

            public MapEntry<TKey, TValue>[] ToArray(MapEntry<TKey, TValue>[] empty)
            {
                return _dictionaryMap._dictionary.Select(kvp => new MapEntry<TKey, TValue>(kvp)).ToArray();
            }

            public int Size()
            {
                return _dictionaryMap._dictionary.Count;
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
            return _dictionary.Values;
        }

        public bool IsEmpty()
        {
            return _dictionary.Count == 0;
        }

        public Set<TKey> KeySet()
        {
            return new KeySetImpl(this);
        }

        private class KeySetImpl : Set<TKey>
        {
            private readonly DictionaryMap<TKey, TValue> _dictionaryMap;

            public KeySetImpl(DictionaryMap<TKey, TValue> dictionaryMap)
            {
                _dictionaryMap = dictionaryMap;
            }

            public IEnumerator<TKey> GetEnumerator()
            {
                return _dictionaryMap._dictionary.Keys.GetEnumerator();
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
                return _dictionaryMap.IsEmpty();
            }

            public bool Contains(TKey value)
            {
                return _dictionaryMap._dictionary.ContainsKey(value);
            }

            public bool ContainsAll(Collection<TKey> other)
            {
                return other.All(Contains);
            }

            public TKey[] ToArray(TKey[] empty)
            {
                return _dictionaryMap._dictionary.Keys.ToArray();
            }

            public int Size()
            {
                return _dictionaryMap._dictionary.Count;
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
