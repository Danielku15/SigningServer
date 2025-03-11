using System;
using SigningServer.Android.IO;

namespace SigningServer.Android.Util.Zip
{
    internal class ZipInputStream : IDisposable
    {
        private ICSharpCode.SharpZipLib.Zip.ZipInputStream mInput;

        public ZipInputStream(InputStream input)
        {
            mInput = new ICSharpCode.SharpZipLib.Zip.ZipInputStream(input.AsStream());
        }

        public ZipEntry GetNextEntry()
        {
            return new ZipEntry(mInput.GetNextEntry());
        }

        public void Dispose()
        {
            mInput?.Dispose();
        }
    }
}