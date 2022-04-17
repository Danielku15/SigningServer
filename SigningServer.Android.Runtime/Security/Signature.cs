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
        private readonly string mJcaSignatureAlgorithm;
        private Signature mSignature;

        public KeyBasedSignature(string jcaSignatureAlgorithm)
        {
            mJcaSignatureAlgorithm = jcaSignatureAlgorithm;
        }

        public override void InitVerify(PublicKey publicKey)
        {
            if (publicKey is CryptographyProviderAccessor accessor)
            {
                mSignature = accessor.Provider.CreateSignature(mJcaSignatureAlgorithm);
                mSignature.InitVerify(publicKey);
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
                mSignature = accessor.Provider.CreateSignature(mJcaSignatureAlgorithm);
                mSignature.InitSign(privateKey);
            }
            else
            {
                throw new ArgumentException("Need key which implements CryptographyProviderAccessor");
            }
        }

        public override void SetParameter(AlgorithmParameterSpec signatureAlgorithmParams)
        {
            mSignature.SetParameter(signatureAlgorithmParams);
        }

        public override void Update(byte data)
        {
            mSignature.Update(data);
        }

        public override void Update(ByteBuffer data)
        {
            mSignature.Update(data);
        }

        public override void Update(byte[] data)
        {
            mSignature.Update(data);
        }

        public override bool Verify(byte[] signature)
        {
            return mSignature.Verify(signature);
        }

        public override byte[] Sign()
        {
            return mSignature.Sign();
        }
    }
}