namespace SigningServer.Android.Util.Zip
{
    internal class ZipEntry
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