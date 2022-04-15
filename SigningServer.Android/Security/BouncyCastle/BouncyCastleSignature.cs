using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using SigningServer.Android.IO;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security.BouncyCastle
{
    public class BouncyCastleSignature : Signature
    {
        private readonly ISigner mSigner;

        public BouncyCastleSignature(string jcaSignatureAlgorithm)
        {
            mSigner = SignerUtilities.GetSigner(jcaSignatureAlgorithm);
        }

        public override void InitVerify(PublicKey publicKey)
        {
            if(!(publicKey is BouncyCastlePublicKey bouncyPublic))
            {
                throw new ArgumentException("Need bouncy castle public key");
            }
            mSigner.Init(false, bouncyPublic.KeyParameter);
        }

        public override void InitSign(PrivateKey privateKey)
        {
            if(!(privateKey is BouncyCastlePrivateKey bouncyPublic))
            {
                throw new ArgumentException("Need bouncy castle public key");
            }
            mSigner.Init(true, bouncyPublic.KeyParameter);
        }

        public override void SetParameter(AlgorithmParameterSpec signatureAlgorithmParams)
        {
            // Ignore
        }

        public override void Update(sbyte data)
        {
            mSigner.Update((byte)data);
        }

        public override void Update(ByteBuffer data)
        {
            if (data.HasArray())
            {
                mSigner.BlockUpdate(data.Array().AsBytes(), data.ArrayOffset() + data.Position(),
                    data.Limit() - data.Position());
            }
            else
            {
                throw new InvalidOperationException("ByteBuffer without array");
            }
        }

        public override void Update(sbyte[] data)
        {
            mSigner.BlockUpdate(data.AsBytes(), 0, data.Length);
        }

        public override bool Verify(sbyte[] signature)
        {
            return mSigner.VerifySignature(signature.AsBytes());
        }

        public override sbyte[] Sign()
        {
            return mSigner.GenerateSignature().AsSBytes();
        }
    }
}