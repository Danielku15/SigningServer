namespace SigningServer.Android.Util.Zip
{
    public class Inflater
    {
        private readonly ICSharpCode.SharpZipLib.Zip.Compression.Inflater mInflater;

        public Inflater(bool nowrap)
        {
            mInflater = new ICSharpCode.SharpZipLib.Zip.Compression.Inflater(nowrap);
        }

        public void SetInput(sbyte[] buf, int offset, int length)
        {
            mInflater.SetInput(buf.AsBytes(), offset, length);
        }

        public bool Finished()
        {
            return mInflater.IsFinished;
        }

        public int Inflate(sbyte[] outputBuffer)
        {
            return mInflater.Inflate(outputBuffer.AsBytes());
        }

        public void End()
        {
            mInflater.Reset();
        }
    }
}