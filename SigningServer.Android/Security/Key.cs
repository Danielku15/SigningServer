namespace SigningServer.Android.Security
{
    public interface Key
    {
        sbyte[] GetEncoded();
        string GetFormat();
        string GetAlgorithm();
    }
}