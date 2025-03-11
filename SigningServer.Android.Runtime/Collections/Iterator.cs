namespace SigningServer.Android.Collections
{
    internal interface Iterator<out T>
    {
        void Remove();
        bool HasNext();
        T Next();
    }
}