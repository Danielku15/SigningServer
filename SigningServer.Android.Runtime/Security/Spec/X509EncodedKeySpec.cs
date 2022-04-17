namespace SigningServer.Android.Security.Spec
{
    internal class X509EncodedKeySpec : KeySpec
    {
        private readonly byte[] _data;

        public X509EncodedKeySpec(byte[] data)
        {
            _data = data;
        }

        public byte[] GetEncoded()
        {
            return (byte[])_data.Clone();
        }
    }
}
