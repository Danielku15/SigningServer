using System;

namespace SigningServer.Android.Util.Zip
{
    public class Inflater
    {
        private readonly ICSharpCode.SharpZipLib.Zip.Compression.Inflater mInflater;

        public Inflater(bool nowrap)
        {
            mInflater = new ICSharpCode.SharpZipLib.Zip.Compression.Inflater(nowrap);
        }

        public void SetInput(byte[] buf, int offset, int length)
        {
            mInflater.SetInput(buf, offset, length);
        }

        public bool Finished()
        {
            return mInflater.IsFinished;
        }

        public int Inflate(byte[] outputBuffer)
        {
            return mInflater.Inflate(outputBuffer);
        }

        public void End()
        {
            mInflater.Reset();
        }
    }
}