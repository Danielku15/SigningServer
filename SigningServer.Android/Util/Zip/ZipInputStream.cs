using System;
using SigningServer.Android.IO;

namespace SigningServer.Android.Util.Zip
{
    public class ZipInputStream : IDisposable
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

    public class ZipEntry
    {
        private readonly ICSharpCode.SharpZipLib.Zip.ZipEntry mEntry;

        public ZipEntry(ICSharpCode.SharpZipLib.Zip.ZipEntry entry)
        {
            mEntry = entry;
        }

        public string GetName()
        {
            return mEntry.Name;
        }
    }
}