using System;
using System.Security.Cryptography;
using SigningServer.Android.IO;

namespace SigningServer.Android.Security.Cert
{
    public interface X500Principal : Principal, IEquatable<X500Principal>
    {
        ByteBuffer GetEncoded();
    }
}