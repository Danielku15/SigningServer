using SigningServer.Android.IO;

namespace SigningServer.Android.Security
{
    public abstract class MessageDigest
    {
        public abstract void Update(ByteBuffer data);
        public abstract void Update(sbyte[] data);
        public abstract sbyte[] Digest();
        public abstract int Digest(sbyte[] data, int offset, int length);
        public abstract sbyte[] Digest(sbyte[] data);

        public static MessageDigest GetInstance(string algorithm)
        {
            throw new System.NotImplementedException();
        }
    }
}