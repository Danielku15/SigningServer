namespace SigningServer.Android.Security.Spec
{
    public interface KeySpec
    {
    }

    public class X509EncodedKeySpec : KeySpec
    {
        public X509EncodedKeySpec(sbyte[] data)
        {
        }
    }
}