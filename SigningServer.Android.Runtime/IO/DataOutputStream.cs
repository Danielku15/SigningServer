namespace SigningServer.Android.IO
{
    internal class DataOutputStream : OutputStream
    {
        private readonly OutputStream _output;

        public DataOutputStream(OutputStream output)
        {
            _output = output;
        }

        public void Write(int v)
        {
            _output.Write(v);
        }
        
        public void WriteInt(int v)
        {
            _output.Write((byte)(TypeUtils.UnsignedRightShift(v, 24) & 0xFF));
            _output.Write((byte)(TypeUtils.UnsignedRightShift(v, 16) & 0xFF));
            _output.Write((byte)(TypeUtils.UnsignedRightShift(v,  8) & 0xFF));
            _output.Write((byte)(TypeUtils.UnsignedRightShift(v,  0) & 0xFF));
        }

        public void Dispose()
        {
            _output.Dispose();
        }

        public void Write(byte[] bytes)
        {
            _output.Write(bytes);
        }

        public void Write(byte[] bytes, int offset, int length)
        {
            _output.Write(bytes, offset, length);
        }
    }
}
