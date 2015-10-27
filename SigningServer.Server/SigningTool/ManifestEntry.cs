namespace SigningServer.Server.SigningTool
{
    public class ManifestEntry
    {
        public string Key { get; set; }
        public string Value { get; set; }

        public ManifestEntry(string key = null, string value = null)
        {
            Key = key;
            Value = value;
        }
    }
}