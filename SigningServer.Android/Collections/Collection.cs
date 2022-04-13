using System.Collections.Generic;

namespace SigningServer.Android.Collections
{
    public interface Collection<T> : IEnumerable<T>
    {
        bool IsEmpty();
    }
}