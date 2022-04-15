using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public interface Set<T> : IEnumerable<T>
    {
        bool Add(T value);
        bool IsEmpty();
        bool Contains(T value);
        T[] ToArray(T[] empty);
        int Size();
    }

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
    }
}