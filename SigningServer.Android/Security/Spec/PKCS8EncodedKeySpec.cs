namespace SigningServer.Android.Security.Spec
{
    public class PKCS8EncodedKeySpec : KeySpec
    {
        private readonly sbyte[] mData;

        public PKCS8EncodedKeySpec(sbyte[] data)
        {
            mData = data;
        }

        public sbyte[] GetEncoded()
        {
            return (sbyte[])mData.Clone();
        }
    }
}