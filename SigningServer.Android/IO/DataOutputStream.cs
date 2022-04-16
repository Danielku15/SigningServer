namespace SigningServer.Android.IO
{
    public class DataOutputStream : OutputStream
    {
        private readonly OutputStream mOutput;

        public DataOutputStream(OutputStream output)
        {
            mOutput = output;
        }

        public void Write(int v)
        {
            mOutput.Write(v);
        }
        
        public void WriteInt(int v)
        {
            mOutput.Write((byte)(TypeUtils.UnsignedRightShift(v, 24) & 0xFF));
            mOutput.Write((byte)(TypeUtils.UnsignedRightShift(v, 16) & 0xFF));
            mOutput.Write((byte)(TypeUtils.UnsignedRightShift(v,  8) & 0xFF));
            mOutput.Write((byte)(TypeUtils.UnsignedRightShift(v,  0) & 0xFF));
        }

        public void Dispose()
        {
            mOutput.Dispose();
        }

        public void Write(byte[] bytes)
        {
            mOutput.Write(bytes);
        }

        public void Write(byte[] bytes, int offset, int length)
        {
            mOutput.Write(bytes, offset, length);
        }
    }
}