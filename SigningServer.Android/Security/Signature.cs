using SigningServer.Android.IO;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security
{
    public class Signature
    {
        public static Signature GetInstance(string jcaSignatureAlgorithm)
        {
            throw new System.NotImplementedException();
        }
        
        public void InitVerify(PublicKey publicKey)
        {
        }

        public void SetParameter(AlgorithmParameterSpec jcaSignatureAlgorithmParams)
        {
        }

        public void Update(ByteBuffer signedData)
        {
        }

        public bool Verify(sbyte[] signature)
        {
        }

        public void Update(sbyte[] signedData)
        {
        }

        public void InitSign(PrivateKey privateKey)
        {
        }

        public sbyte[] Sign()
        {
        }

        public void Update(sbyte b)
        {
        }
    }
}