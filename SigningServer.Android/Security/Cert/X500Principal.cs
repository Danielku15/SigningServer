using System;
using System.Security.Cryptography.X509Certificates;
using SigningServer.Android.IO;

namespace SigningServer.Android.Security.Cert
{
    public class X500Principal : Principal, IEquatable<X500Principal>
    {
        private readonly X500DistinguishedName mName;

        public X500Principal(sbyte[] encoded)
        {
            mName = new X500DistinguishedName(encoded.AsBytes());
        }

        public ByteBuffer GetEncoded()
        {
            return ByteBuffer.Wrap(mName.RawData.AsSBytes());
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