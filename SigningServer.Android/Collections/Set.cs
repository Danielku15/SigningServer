namespace SigningServer.Android.Collections
{
    public interface Set<T> : Collection<T>
    {
        bool IsEmpty();
        bool Contains(T value);
        // ReSharper disable once UnusedParameter.Global
        T[] ToArray(T[] empty);
        int Size();
        bool Remove(T value);
    }
}