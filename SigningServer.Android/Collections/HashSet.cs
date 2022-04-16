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