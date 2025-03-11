namespace SigningServer.Android.Util.Zip
{
    internal class ZipEntry
    {
        private readonly ICSharpCode.SharpZipLib.Zip.ZipEntry _entry;

        public ZipEntry(ICSharpCode.SharpZipLib.Zip.ZipEntry entry)
        {
            _entry = entry;
        }

        public string GetName()
        {
            return _entry.Name;
        }
    }
}
