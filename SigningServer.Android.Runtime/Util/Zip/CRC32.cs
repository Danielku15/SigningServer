using System;
using ICSharpCode.SharpZipLib.Checksum;

namespace SigningServer.Android.Util.Zip
{
    internal class CRC32
    {
        private readonly Crc32 mCrc;

        public CRC32()
        {
            mCrc = new Crc32();
        }
        
        public void Update(byte[] data, int offset, int length)
        {
            mCrc.Update(new ArraySegment<byte>(data, offset, length));
        }

        public long GetValue()
        {
            return mCrc.Value;
        }
    }
}