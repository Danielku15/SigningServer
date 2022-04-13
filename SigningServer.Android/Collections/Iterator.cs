using SigningServer.Android.Com.Android.Apksig.Internal.Apk;

namespace SigningServer.Android.Collections
{
    public interface Iterator<T>
    {
        void Remove();
        bool HasNext();
        T Next();
    }
}