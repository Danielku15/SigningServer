using System.Collections.Generic;
using SigningServer.Android.Com.Android.Apksig.Internal.Util;

namespace SigningServer.Android.Collections
{
    public interface Collection<T> : IEnumerable<T>
    {
        bool IsEmpty();
        int Size();
        void Add(T guaranteedEncodedCert);
    }
}