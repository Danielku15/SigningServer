using System;
using System.Security.Cryptography.X509Certificates;
using SigningServer.Android.IO;

namespace SigningServer.Android.Security.Cert
{
    public class X500Principal : Principal, IEquatable<X500Principal>
    {
        private readonly X500DistinguishedName _name;

        public X500Principal(byte[] encoded)
        {
            _name = new X500DistinguishedName(encoded);
        }
        public X500Principal(X500DistinguishedName name)
        {
            _name = name;
        }

        public ByteBuffer GetEncoded()
        {
            return ByteBuffer.Wrap(_name.RawData);
        }

        public string GetName()
        {
            return _name.Name;
        }

        public bool Equals(X500Principal other)
        {
            return _name.Name == other._name.Name;
        }
    }
}
