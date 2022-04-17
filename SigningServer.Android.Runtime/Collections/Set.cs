namespace SigningServer.Android.Collections
{
    public interface Set<T> : Collection<T>
    {
        bool Contains(T value);
        // ReSharper disable once UnusedParameter.Global
        T[] ToArray(T[] empty);
        bool Remove(T value);
    }
}