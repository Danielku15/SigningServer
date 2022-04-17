using System;
using System.Security.Cryptography;
using SigningServer.Android.IO;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security.DotNet
{
    internal class DotNetSignature : Signature
    {
        private DotNetPublicKey _publicKey;
        private DotNetPrivateKey _privateKey;
        private readonly MessageDigest _messageDigest;

        public DotNetSignature(string jcaSignatureAlgorithm)
        {
            if (jcaSignatureAlgorithm.StartsWith("SHA512", StringComparison.OrdinalIgnoreCase))
            {
                _messageDigest = MessageDigest.GetInstance("SHA-512");
            }
            else if (jcaSignatureAlgorithm.StartsWith("SHA256", StringComparison.OrdinalIgnoreCase))
            {
                _messageDigest = MessageDigest.GetInstance("SHA-256");
            }
            else if (jcaSignatureAlgorithm.StartsWith("SHA1", StringComparison.OrdinalIgnoreCase))
            {
                _messageDigest = MessageDigest.GetInstance("SHA-1");
            }
            else if (jcaSignatureAlgorithm.StartsWith("MD5", StringComparison.OrdinalIgnoreCase))
            {
                _messageDigest = MessageDigest.GetInstance("MD5");
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

            _publicKey = dotNetPublic;
        }

        public override void InitSign(PrivateKey privateKey)
        {
            if (!(privateKey is DotNetPrivateKey dotNetPrivate))
            {
                throw new ArgumentException("Need DotNet private key");
            }

            _privateKey = dotNetPrivate;
        }

        public override void SetParameter(AlgorithmParameterSpec signatureAlgorithmParams)
        {
            // Ignore
        }

        public override void Update(byte data)
        {
            _messageDigest.Update(new[] { data });
        }

        public override void Update(ByteBuffer data)
        {
            _messageDigest.Update(data);
        }

        public override void Update(byte[] data)
        {
            _messageDigest.Update(data);
        }

        public override bool Verify(byte[] signature)
        {
            return _publicKey.VerifyHash(_messageDigest.Digest(), GetHashAlgorithmName(_messageDigest), signature);
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
            return _privateKey.SignHash(_messageDigest.Digest(), GetHashAlgorithmName(_messageDigest));
        }
    }
}
