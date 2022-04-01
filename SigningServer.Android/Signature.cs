using System.Security.Cryptography;

namespace SigningServer.Android
{
    public class Signature
    {
        public static Signature getInstance(string jcaSignatureAlgorithm)
        {
            throw new System.NotImplementedException();
        }

        public void initVerify(PublicKey publicKey)
        {
            throw new System.NotImplementedException();
        }

        public void setParameter(AlgorithmParameterSpec jcaSignatureAlgorithmParams)
        {
            throw new System.NotImplementedException();
        }

        public void update(ByteBuffer signedData)
        {
            throw new System.NotImplementedException();
        }

        public bool verify(byte[] signature)
        {
            throw new System.NotImplementedException();
        }

        public void update(byte[] signedData)
        {
            throw new System.NotImplementedException();
        }

        public void initSign(PrivateKey signerConfigPrivateKey)
        {
            throw new System.NotImplementedException();
        }

        public byte[] sign()
        {
            throw new System.NotImplementedException();
        }

        public void update(byte b)
        {
            throw new System.NotImplementedException();
        }
    }
}