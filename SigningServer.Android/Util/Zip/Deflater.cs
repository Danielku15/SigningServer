namespace SigningServer.Android.Util.Zip
{
    public class Deflater
    {
        private readonly ICSharpCode.SharpZipLib.Zip.Compression.Deflater mDeflater;

        public Deflater(int level, bool nowrap)
        {
            mDeflater = new ICSharpCode.SharpZipLib.Zip.Compression.Deflater(level, nowrap);
        }

        public void SetInput(sbyte[] inputBuf, int inputOffset, int inputLength)
        {
            mDeflater.SetInput(inputBuf.AsBytes(), inputOffset, inputLength);
        }

        public void Finish()
        {
            mDeflater.Finish();
        }

        public bool Finished()
        {
            return mDeflater.IsFinished;
        }

        public int Deflate(sbyte[] buf)
        {
            return mDeflater.Deflate(buf.AsBytes());
        }
    }
}