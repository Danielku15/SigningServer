namespace SigningServer.Android.Security.Spec
{
    public class X509EncodedKeySpec : KeySpec
    {
        private readonly sbyte[] mData;

        public X509EncodedKeySpec(sbyte[] data)
        {
            mData = data;
        }

        public sbyte[] GetEncoded()
        {
            return (sbyte[])mData.Clone();
        }
    }
}