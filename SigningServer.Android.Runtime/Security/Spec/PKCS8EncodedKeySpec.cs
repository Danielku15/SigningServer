namespace SigningServer.Android.Security.Spec
{
    internal class PKCS8EncodedKeySpec : KeySpec
    {
        private readonly byte[] mData;

        public PKCS8EncodedKeySpec(byte[] data)
        {
            mData = data;
        }

        public byte[] GetEncoded()
        {
            return (byte[])mData.Clone();
        }
    }
}