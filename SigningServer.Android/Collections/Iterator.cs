namespace SigningServer.Android.Collections
{
    public interface Iterator<out T>
    {
        void Remove();
        bool HasNext();
        T Next();
    }
}