using System;
using ICSharpCode.SharpZipLib.Checksum;

namespace SigningServer.Android.Util.Zip
{
    internal class CRC32
    {
        private readonly Crc32 _crc;

        public CRC32()
        {
            _crc = new Crc32();
        }
        
        public void Update(byte[] data, int offset, int length)
        {
            _crc.Update(new ArraySegment<byte>(data, offset, length));
        }

        public long GetValue()
        {
            return _crc.Value;
        }
    }
}
