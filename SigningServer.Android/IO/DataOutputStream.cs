namespace SigningServer.Android.IO
{
    public class DataOutputStream : OutputStream
    {
        private readonly OutputStream mOutput;

        public DataOutputStream(OutputStream output)
        {
            mOutput = output;
        }

        public void WriteInt(int clampToInt)
        {
            throw new System.NotImplementedException();
        }
    }
}