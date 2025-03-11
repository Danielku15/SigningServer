using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using SigningServer.Android.Core;
using SigningServer.Android.IO;

namespace SigningServer.Android.Security
{
    public class MessageDigest
    {
        private readonly IDigest _digest;

        public MessageDigest(IDigest digest)
        {
            _digest = digest;
        }

        public void Update(ByteBuffer data)
        {
            if (data.HasArray())
            {
                _digest.BlockUpdate(data.Array(), data.ArrayOffset() + data.Position(),
                    data.Limit() - data.Position());
            }
            else
            {
                throw new InvalidOperationException("ByteBuffer without array");
            }
        }

        public void Update(byte[] data)
        {
            _digest.BlockUpdate(data, 0, data.Length);
        }

        public byte[] Digest()
        {
            var result = new byte[_digest.GetDigestSize()];
            _digest.DoFinal(result, 0);
            _digest.Reset();
            return result;
        }

        public int Digest(byte[] data, int offset, int length)
        {
            _digest.DoFinal(data, offset);
            _digest.Reset();
            return _digest.GetDigestSize();
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
            _digest.BlockUpdate(data, offset, length);
        }

        public string GetAlgorithm()
        {
            return _digest.AlgorithmName;
        }

        public int GetDigestLength()
        {
            return _digest.GetDigestSize();
        }

        public void Reset()
        {
            _digest.Reset();
        }

        public MessageDigest Clone()
        {
            throw new CloneNotSupportedException();
        }
    }
}
