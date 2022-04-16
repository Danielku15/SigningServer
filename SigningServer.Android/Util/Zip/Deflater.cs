using System;
using System.IO;
using Org.BouncyCastle.Utilities.Zlib;

namespace SigningServer.Android.Util.Zip
{
    public class Deflater
    {
        // NOTE: SharpZipLib deflater delivers different results than libs using ZLib. need 1:1 binary
        // equality with ZLib for golden tests.
        private ArraySegment<byte> mInput;
        private readonly ZOutputStream mDeflater;
        private readonly MemoryStream mOut;

        public Deflater(int level, bool nowrap)
        {
            mOut = new MemoryStream();
            mDeflater = new ZOutputStream(mOut, level, nowrap);
        }

        public void SetInput(byte[] inputBuf, int inputOffset, int inputLength)
        {
            mInput = new ArraySegment<byte>(inputBuf, inputOffset, inputLength);
        }

        public void Finish()
        {
            mDeflater.Write(mInput.Array, mInput.Offset, mInput.Count);
            mDeflater.Finish();
            mOut.Position = 0;
            mFinished = mOut.Position >= mOut.Length;
        }

        private bool mFinished = false;
        public bool Finished()
        {
            return mFinished;
        }

        public int Deflate(byte[] buf)
        {
            var c = mOut.Read(buf, 0, buf.Length);
            if (mOut.Position >= mOut.Length)
            {
                mFinished = true;
                mDeflater.Dispose();
            }

            return c;
        }
    }
}