using System;
using System.Collections.Generic;
using System.Linq;

namespace SigningServer.Android.Collections
{
    public class List<T> : System.Collections.Generic.List<T>, Collection<T>
    {
        public List()
        {
        }

        public List(int capacity) : base(capacity)
        {
        }

        public List(IEnumerable<T> other) : base(other)
        {
        }

        public void Remove(int index)
        {
            RemoveAt(index);
        }

        bool Collection<T>.Add(T value)
        {
            base.Add(value);
            return true;
        }

        public bool ContainsAll(Collection<T> other)
        {
            return other.All(Contains);
        }

        public T Get(int index)
        {
            return this[index];
        }

        public bool IsEmpty()
        {
            return Count == 0;
        }

        public void AddAll(IEnumerable<T> items)
        {
            AddRange(items);
        }

        // ReSharper disable once UnusedParameter.Global
        public T[] ToArray(T[] unused)
        {
            return ToArray();
        }

        public int Size()
        {
            return Count;
        }

        public ListIteratorImpl ListIterator()
        {
            return new ListIteratorImpl(this);
        }

        public class ListIteratorImpl : Iterator<T>
        {
            private readonly List<T> _list;
            private int _cursor;
            private int _lastRet = -1; // index of last element returned; -1 if no such

            public ListIteratorImpl(List<T> list)
            {
                _list = list;
            }

            public void Remove()
            {
                if (_lastRet < 0)
                    throw new InvalidOperationException();

                _list.Remove(_lastRet);
                _cursor = _lastRet;
                _lastRet = -1;
            }


            public bool HasNext()
            {
                return _cursor != _list.Count;
            }

            public T Next()
            {
                var i = _cursor;
                if (i >= _list.Count)
                    throw new IndexOutOfRangeException();
                _cursor = i + 1;

                return _list[_lastRet = i];
            }
        }

        public bool ContainsAll(List<T> other)
        {
            return other.All(Contains);
        }

        public List<T> SubList(int fromIndex, int toIndex)
        {
            return new List<T>(GetRange(fromIndex, toIndex - fromIndex));
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
                hashCode = 31 * hashCode + (item == null ? 0 : item.GetHashCode());
            }

            return hashCode;
        }
    }
}
