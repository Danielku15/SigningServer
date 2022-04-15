using System.Collections.Generic;
using System.Linq;

namespace SigningServer.Android.Collections
{
    public class HashSet<T> : System.Collections.Generic.HashSet<T>, Set<T>
    {
        public HashSet()
        {
        }

        public HashSet(int capacity) : base(capacity)
        {
        }

        public HashSet(IEnumerable<T> items) : base(items)
        {
        }

        public bool ContainsAll(Collection<T> other)
        {
            return other.All(Contains);
        }

        public bool IsEmpty()
        {
            return Count == 0;
        }

        public T[] ToArray(T[] empty)
        {
            return this.ToArray();
        }

        public int Size()
        {
            return Count;
        }
    }
}