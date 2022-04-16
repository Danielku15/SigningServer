namespace SigningServer.Android.Security
{
    public interface Key
    {
        byte[] GetEncoded();
        string GetFormat();
        string GetAlgorithm();
    }
}