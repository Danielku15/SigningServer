using System;
using System.Security.Cryptography;
using SigningServer.Android.IO;

namespace SigningServer.Android.Security.Cert
{
    public class X500Principal : Principal, IEquatable<X500Principal>
    {
        public X500Principal(sbyte[] encodedIssuer)
        {
            throw new NotImplementedException();
        }

        public ByteBuffer GetEncoded();
    }
}