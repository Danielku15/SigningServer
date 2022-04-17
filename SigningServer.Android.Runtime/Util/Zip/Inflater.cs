namespace SigningServer.Android.Util.Zip
{
    internal class Inflater
    {
        private readonly ICSharpCode.SharpZipLib.Zip.Compression.Inflater _inflater;

        public Inflater(bool nowrap)
        {
            _inflater = new ICSharpCode.SharpZipLib.Zip.Compression.Inflater(nowrap);
        }

        public void SetInput(byte[] buf, int offset, int length)
        {
            _inflater.SetInput(buf, offset, length);
        }

        public bool Finished()
        {
            return _inflater.IsFinished;
        }

        public int Inflate(byte[] outputBuffer)
        {
            return _inflater.Inflate(outputBuffer);
        }

        public void End()
        {
            _inflater.Reset();
        }
    }
}
