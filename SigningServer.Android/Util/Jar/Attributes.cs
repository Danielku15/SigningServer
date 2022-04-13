using System.Collections.Generic;
using SigningServer.Android.Collections;

namespace SigningServer.Android.Util.Jar
{
    public class Attributes : HashMap<Attributes.Name, string>
    {
        public class Name
        {
            private readonly string mName;

            public Name(string name)
            {
                mName = name;
            }

            public static Name MANIFEST_VERSION = new Name("Manifest-Version");
            public static Name SIGNATURE_VERSION = new Name("Signature-Version");

            public override string ToString()
            {
                return mName;
            }
        }

        public string GetValue(Name name)
        {
            throw new System.NotImplementedException();
        }

        public int Size()
        {
            throw new System.NotImplementedException();
        }
        
        
        public void PutValue(string name, string value)
        {
            throw new System.NotImplementedException();
        }
    }
}