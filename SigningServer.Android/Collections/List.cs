using System.Collections.Generic;
using SigningServer.Android.Com.Android.Apksig;
using SigningServer.Android.Com.Android.Apksig.Internal.Apk;

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
            base.AddRange(items);
        }

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
            throw new System.NotImplementedException();
        }

        public class ListIteratorImpl : Iterator<T>
        {
        }
    }
}