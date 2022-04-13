using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public interface Set<T> : IEnumerable<T>
    {
        void Add(T value);
        bool IsEmpty();
        bool Contains(T value);
    }

    public class HashSet<T> : System.Collections.Generic.HashSet<T>, Set<T>
    {
        public HashSet()
        {
        }

        public HashSet(int capacity) : base(capacity)
        {
        }
    }
}