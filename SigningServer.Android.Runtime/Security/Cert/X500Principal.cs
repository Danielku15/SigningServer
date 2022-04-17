using System;
using System.Security.Cryptography.X509Certificates;
using SigningServer.Android.IO;

namespace SigningServer.Android.Security.Cert
{
    public class X500Principal : Principal, IEquatable<X500Principal>
    {
        private readonly X500DistinguishedName mName;

        public X500Principal(byte[] encoded)
        {
            mName = new X500DistinguishedName(encoded);
        }
        public X500Principal(X500DistinguishedName name)
        {
            mName = name;
        }

        public ByteBuffer GetEncoded()
        {
            return ByteBuffer.Wrap(mName.RawData);
        }

        public string GetName()
        {
            return mName.Name;
        }

        public bool Equals(X500Principal other)
        {
            return mName.Name == other.mName.Name;
        }
    }
}