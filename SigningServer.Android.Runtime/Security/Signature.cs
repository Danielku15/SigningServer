using System;
using SigningServer.Android.IO;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security
{
    public abstract class Signature
    {
        public static Signature GetInstance(string jcaSignatureAlgorithm)
        {
            return new KeyBasedSignature(jcaSignatureAlgorithm);
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
    
    internal class KeyBasedSignature : Signature
    {
        private readonly string _jcaSignatureAlgorithm;
        private Signature _signature;

        public KeyBasedSignature(string jcaSignatureAlgorithm)
        {
            _jcaSignatureAlgorithm = jcaSignatureAlgorithm;
        }

        public override void InitVerify(PublicKey publicKey)
        {
            if (publicKey is CryptographyProviderAccessor accessor)
            {
                _signature = accessor.Provider.CreateSignature(_jcaSignatureAlgorithm);
                _signature.InitVerify(publicKey);
            }
            else
            {
                throw new ArgumentException("Need key which implements CryptographyProviderAccessor");
            }
        }

        public override void InitSign(PrivateKey privateKey)
        {
            if (privateKey is CryptographyProviderAccessor accessor)
            {
                _signature = accessor.Provider.CreateSignature(_jcaSignatureAlgorithm);
                _signature.InitSign(privateKey);
            }
            else
            {
                throw new ArgumentException("Need key which implements CryptographyProviderAccessor");
            }
        }

        public override void SetParameter(AlgorithmParameterSpec signatureAlgorithmParams)
        {
            _signature.SetParameter(signatureAlgorithmParams);
        }

        public override void Update(byte data)
        {
            _signature.Update(data);
        }

        public override void Update(ByteBuffer data)
        {
            _signature.Update(data);
        }

        public override void Update(byte[] data)
        {
            _signature.Update(data);
        }

        public override bool Verify(byte[] signature)
        {
            return _signature.Verify(signature);
        }

        public override byte[] Sign()
        {
            return _signature.Sign();
        }
    }
}
