using SigningServer.Android.Collections;

namespace SigningServer.Android.Util.Jar
{
    public class Attributes : HashMap<Attributes.Name, string>
    {
        public class Name
        {
            // ReSharper disable InconsistentNaming
            public static readonly Name MANIFEST_VERSION = new Name("Manifest-Version");
            public static readonly Name SIGNATURE_VERSION = new Name("Signature-Version");
            // ReSharper restore InconsistentNaming

            private readonly string _name;

            public Name(string name)
            {
                _name = name;
            }

            public override string ToString()
            {
                return _name;
            }

            protected bool Equals(Name other)
            {
                return _name == other._name;
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
                return (_name != null ? _name.GetHashCode() : 0);
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
