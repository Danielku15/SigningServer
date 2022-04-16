using SigningServer.Android.IO;
using SigningServer.Android.Security.BouncyCastle;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security
{
    public abstract class Signature
    {
        public static Signature GetInstance(string jcaSignatureAlgorithm)
        {
            return new BouncyCastleSignature(jcaSignatureAlgorithm);
        }

        public abstract void InitVerify(PublicKey publicKey);
        public abstract void InitSign(PrivateKey privateKey);
        public abstract void SetParameter(AlgorithmParameterSpec signatureAlgorithmParams);
        public abstract void Update(byte data);
        public abstract void Update(ByteBuffer data);
        public abstract void Update(byte[] data);
        public abstract bool Verify(byte[] signature);
        public abstract byte[] Sign();
    }
}