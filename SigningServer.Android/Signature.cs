using System.IO;
using System.Security.Cryptography;

namespace SigningServer.Android
{
    public class Signature
    {
        private readonly string mJcaSignatureAlgorithm;
        private PublicKey mPublicKey;
        private MemoryStream mData = new MemoryStream();
        private AlgorithmParameterSpec mParameter;
        private PrivateKey mPrivateKey;

        private Signature(string jcaSignatureAlgorithm)
        {
            mJcaSignatureAlgorithm = jcaSignatureAlgorithm;
        }

        public static Signature getInstance(string jcaSignatureAlgorithm)
        {
            return new Signature(jcaSignatureAlgorithm);
        }

        public void initVerify(PublicKey publicKey)
        {
            mPublicKey = publicKey;
        }

        public void setParameter(AlgorithmParameterSpec jcaSignatureAlgorithmParams)
        {
            mParameter = jcaSignatureAlgorithmParams;
        }

        public void update(ByteBuffer signedData)
        {
            var raw = new byte[signedData.remaining()];
            signedData.get(raw);
            update(raw);
        }

        public bool verify(byte[] signature)
        {
            return mPublicKey.verify(mData.ToArray(), signature, mJcaSignatureAlgorithm);
        }

        public void update(byte[] signedData)
        {
            mData.Write(signedData, 0, signedData.Length);
        }

        public void initSign(PrivateKey privateKey)
        {
            mPrivateKey = privateKey;
        }

        public byte[] sign()
        {
            return mPrivateKey.sign(mData.ToArray(), mJcaSignatureAlgorithm);
        }

        public void update(byte b)
        {
            mData.WriteByte(b);
        }
    }
}