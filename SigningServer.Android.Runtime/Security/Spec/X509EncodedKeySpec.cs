namespace SigningServer.Android.Security.Spec
{
    internal class X509EncodedKeySpec : KeySpec
    {
        private readonly byte[] mData;

        public X509EncodedKeySpec(byte[] data)
        {
            mData = data;
        }

        public byte[] GetEncoded()
        {
            return (byte[])mData.Clone();
        }
    }
}