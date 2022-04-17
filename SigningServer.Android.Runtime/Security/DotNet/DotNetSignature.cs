using System;
using System.Security.Cryptography;
using SigningServer.Android.IO;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security.DotNet
{
    public class DotNetSignature : Signature
    {
        private DotNetPublicKey mPublicKey;
        private DotNetPrivateKey mPrivateKey;
        private readonly MessageDigest mMessageDigest;

        public DotNetSignature(string jcaSignatureAlgorithm)
        {
            if (jcaSignatureAlgorithm.StartsWith("SHA512", StringComparison.OrdinalIgnoreCase))
            {
                mMessageDigest = MessageDigest.GetInstance("SHA-512");
            }
            else if (jcaSignatureAlgorithm.StartsWith("SHA256", StringComparison.OrdinalIgnoreCase))
            {
                mMessageDigest = MessageDigest.GetInstance("SHA-256");
            }
            else if (jcaSignatureAlgorithm.StartsWith("SHA1", StringComparison.OrdinalIgnoreCase))
            {
                mMessageDigest = MessageDigest.GetInstance("SHA-1");
            }
            else if (jcaSignatureAlgorithm.StartsWith("MD5", StringComparison.OrdinalIgnoreCase))
            {
                mMessageDigest = MessageDigest.GetInstance("MD5");
            }
            else
            {
                throw new CryptographicException("Unsupported signature algorithm: " + jcaSignatureAlgorithm);
            }
        }

        public override void InitVerify(PublicKey publicKey)
        {
            if (!(publicKey is DotNetPublicKey dotNetPublic))
            {
                throw new ArgumentException("Need DotNet public key");
            }

            mPublicKey = dotNetPublic;
        }

        public override void InitSign(PrivateKey privateKey)
        {
            if (!(privateKey is DotNetPrivateKey dotNetPrivate))
            {
                throw new ArgumentException("Need DotNet private key");
            }

            mPrivateKey = dotNetPrivate;
        }

        public override void SetParameter(AlgorithmParameterSpec signatureAlgorithmParams)
        {
            // Ignore
        }

        public override void Update(byte data)
        {
            mMessageDigest.Update(new[] { data });
        }

        public override void Update(ByteBuffer data)
        {
            mMessageDigest.Update(data);
        }

        public override void Update(byte[] data)
        {
            mMessageDigest.Update(data);
        }

        public override bool Verify(byte[] signature)
        {
            return mPublicKey.VerifyHash(mMessageDigest.Digest(), GetHashAlgorithmName(mMessageDigest), signature);
        }

        private HashAlgorithmName GetHashAlgorithmName(MessageDigest messageDigest)
        {
            switch (messageDigest.GetAlgorithm())
            {
                case "MD5":
                    return HashAlgorithmName.MD5;
                case "SHA-1":
                    return HashAlgorithmName.SHA1;
                case "SHA-256":
                    return HashAlgorithmName.SHA256;
                case "SHA-384":
                    return HashAlgorithmName.SHA384;
                case "SHA-512":
                    return HashAlgorithmName.SHA512;
            }

            return HashAlgorithmName.SHA256;
        }

        public override byte[] Sign()
        {
            return mPrivateKey.SignHash(mMessageDigest.Digest(), GetHashAlgorithmName(mMessageDigest));
        }
    }
}