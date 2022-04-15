using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public interface Set<T> : IEnumerable<T>
    {
        bool Add(T value);
        bool IsEmpty();
        bool Contains(T value);
        // ReSharper disable once UnusedParameter.Global
        T[] ToArray(T[] empty);
        int Size();
    }
}