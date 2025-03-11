using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public interface Collection<T> : IEnumerable<T>
    {
        bool IsEmpty();
        int Size();
        bool Add(T value);
        bool ContainsAll(Collection<T> other);
    }
}