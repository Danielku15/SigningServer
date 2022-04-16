using SigningServer.Android.Collections;

namespace SigningServer.Android.Util.Jar
{
    public class Attributes : HashMap<Attributes.Name, string>
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

            protected bool Equals(Name other)
            {
                return mName == other.mName;
            }

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj)) return false;
                if (ReferenceEquals(this, obj)) return true;
                if (obj.GetType() != this.GetType()) return false;
                return Equals((Name)obj);
            }

            public override int GetHashCode()
            {
                return (mName != null ? mName.GetHashCode() : 0);
            }
        }

        public string GetValue(Name name)
        {
            return Get(name);
        }

        public void PutValue(string name, string value)
        {
            Put(new Name(name), value);
        }

        public void PutAll(Attributes attributes)
        {
            foreach (var attribute in attributes.EntrySet())
            {
                Put(attribute.GetKey(), attribute.GetValue());
            }
        }
    }
}