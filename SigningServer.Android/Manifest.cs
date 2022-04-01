using System.Collections;
using System.IO;
using SigningServer.Android.ApkSig.Internal.Jar;

namespace SigningServer.Android
{
    public class Manifest
    {
        public Manifest()
        {
        }
        public Manifest(Stream memoryStream)
        {
            throw new System.NotImplementedException();
        }

        public Attributes getMainAttributes()
        {
            throw new System.NotImplementedException();
        }
    }
}