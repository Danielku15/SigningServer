using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using SigningServer.Android.Core;
using SigningServer.Android.IO;

namespace SigningServer.Android.Security
{
    public class MessageDigest
    {
        private readonly IDigest mDigest;

        public MessageDigest(IDigest digest)
        {
            mDigest = digest;
        }

        public void Update(ByteBuffer data)
        {
            if (data.HasArray())
            {
                mDigest.BlockUpdate(data.Array(), data.ArrayOffset() + data.Position(),
                    data.Limit() - data.Position());
            }
            else
            {
                throw new InvalidOperationException("ByteBuffer without array");
            }
        }

        public void Update(byte[] data)
        {
            mDigest.BlockUpdate(data, 0, data.Length);
        }

        public byte[] Digest()
        {
            var result = new byte[mDigest.GetDigestSize()];
            mDigest.DoFinal(result, 0);
            mDigest.Reset();
            return result;
        }

        public int Digest(byte[] data, int offset, int length)
        {
            mDigest.DoFinal(data, offset);
            mDigest.Reset();
            return mDigest.GetDigestSize();
        }

        public byte[] Digest(byte[] data)
        {
            Update(data);
            return Digest();
        }

        public static MessageDigest GetInstance(string algorithm)
        {
            try
            {
                return new MessageDigest(DigestUtilities.GetDigest(algorithm));
            }
            catch (SecurityUtilityException e)
            {
                throw new NoSuchAlgorithmException(e.Message, e);
            }
        }

        public void Update(byte[] data, int offset, int length)
        {
            mDigest.BlockUpdate(data, offset, length);
        }

        public string GetAlgorithm()
        {
            return mDigest.AlgorithmName;
        }

        public int GetDigestLength()
        {
            return mDigest.GetDigestSize();
        }

        public void Reset()
        {
            mDigest.Reset();
        }

        public MessageDigest Clone()
        {
            throw new CloneNotSupportedException();
        }
    }
}