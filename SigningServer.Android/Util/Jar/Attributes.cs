using SigningServer.Android.Collections;

namespace SigningServer.Android.Util.Jar
{
    public class Attributes : HashMap<object, object>
    {
        public class Name
        {
            public static readonly Name MANIFEST_VERSION = new Name("Manifest-Version");
            public static readonly Name SIGNATURE_VERSION = new Name("Signature-Version");

            private readonly string mName;

            public Name(string name)
            {
                mName = name;
            }

            public override string ToString()
            {
                return mName;
            }
        }

        public string GetValue(Name name)
        {
            return Get(name.ToString()).ToString();
        }

        public int Size()
        {
            return Count;
        }
        
        public void PutValue(string name, string value)
        {
            this[name] = value;
        }

        public void PutAll(Attributes attributes)
        {
            foreach (var attribute in attributes)
            {
                this[attribute.Key.ToString()] = attribute.Value.ToString();
            }
        }
    }
}