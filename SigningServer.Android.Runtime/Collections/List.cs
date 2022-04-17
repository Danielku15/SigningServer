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
            private readonly List<T> mList;
            private int mCursor = 0;
            private int mLastRet = -1; // index of last element returned; -1 if no such

            public ListIteratorImpl(List<T> list)
            {
                mList = list;
            }

            public void Remove()
            {
                if (mLastRet < 0)
                    throw new InvalidOperationException();

                mList.Remove(mLastRet);
                mCursor = mLastRet;
                mLastRet = -1;
            }


            public bool HasNext()
            {
                return mCursor != mList.Count;
            }

            public T Next()
            {
                var i = mCursor;
                if (i >= mList.Count)
                    throw new IndexOutOfRangeException();
                mCursor = i + 1;

                return mList[mLastRet = i];
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