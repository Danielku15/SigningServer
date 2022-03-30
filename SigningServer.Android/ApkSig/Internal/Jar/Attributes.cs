using System.Collections.Generic;

namespace SigningServer.Android.ApkSig.Internal.Jar
{
    public class Attributes : Dictionary<string, string>
    {
        public class Name
        {
            public static readonly Name MANIFEST_VERSION = new Name("Manifest-Version");
            public static readonly Name SIGNATURE_VERSION = new Name("Signature-Version");

            public string Value { get; }

            public Name(string value)
            {
                Value = value;
            }

            public override string ToString()
            {
                return Value;
            }
        }
        
        public string getValue(string key)
        {
            if (TryGetValue(key, out var value))
            {
                return value;
            }

            return null;
        }
    }
}