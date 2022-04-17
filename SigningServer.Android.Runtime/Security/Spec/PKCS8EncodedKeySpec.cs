namespace SigningServer.Android.Security.Spec
{
    internal class PKCS8EncodedKeySpec : KeySpec
    {
        private readonly byte[] _data;

        public PKCS8EncodedKeySpec(byte[] data)
        {
            _data = data;
        }

        public byte[] GetEncoded()
        {
            return (byte[])_data.Clone();
        }
    }
}
