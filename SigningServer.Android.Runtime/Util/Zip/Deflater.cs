using System;
using System.IO;
using Org.BouncyCastle.Utilities.Zlib;

namespace SigningServer.Android.Util.Zip
{
    internal class Deflater
    {
        // NOTE: SharpZipLib deflater delivers different results than libs using ZLib. need 1:1 binary
        // equality with ZLib for golden tests.
        private ArraySegment<byte> _input;
        private readonly ZOutputStream _deflater;
        private readonly MemoryStream _out;
        private bool _finished;

        public Deflater(int level, bool nowrap)
        {
            _out = new MemoryStream();
            _deflater = new ZOutputStream(_out, level, nowrap);
        }

        public void SetInput(byte[] inputBuf, int inputOffset, int inputLength)
        {
            _input = new ArraySegment<byte>(inputBuf, inputOffset, inputLength);
        }

        public void Finish()
        {
            _deflater.Write(_input.Array, _input.Offset, _input.Count);
            _deflater.Finish();
            _out.Position = 0;
            _finished = _out.Position >= _out.Length;
        }

        public bool Finished()
        {
            return _finished;
        }

        public int Deflate(byte[] buf)
        {
            var c = _out.Read(buf, 0, buf.Length);
            if (_out.Position >= _out.Length)
            {
                _finished = true;
                _deflater.Dispose();
            }

            return c;
        }
    }
}
