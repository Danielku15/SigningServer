using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using SigningServer.Android.IO;
using SigningServer.Android.Security.Spec;

namespace SigningServer.Android.Security.BouncyCastle
{
    internal class BouncyCastleSignature : Signature
    {
        private readonly ISigner _signer;

        public BouncyCastleSignature(string jcaSignatureAlgorithm)
        {
            switch (jcaSignatureAlgorithm.ToUpperInvariant())
            {
                // Deterministic DSA
                // https://github.com/bcgit/bc-java/blob/bc3b92f1f0e78b82e2584c5fb4b226a13e7f8b3b/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/DSA.java#L35
                case "DDSA":
                case "DETDSA":
                case "SHA1WITHDETDSA":
                case "SHA1WITHDDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(new Sha1Digest())), new Sha1Digest());
                    break;
                case "SHA224WITHDETDSA":
                case "SHA224WITHDDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(new Sha224Digest())), new Sha224Digest());
                    break;
                case "SHA256WITHDETDSA":
                case "SHA256WITHDDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(new Sha256Digest())), new Sha256Digest());
                    break;
                case "SHA384WITHDETDSA":
                case "SHA384WITHDDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(new Sha384Digest())), new Sha384Digest());
                    break;
                case "SHA512WITHDETDSA":
                case "SHA512WITHDDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(new Sha512Digest())), new Sha512Digest());
                    break;
                case "SHA3-224WITHDDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(new Sha3Digest(224))), new Sha3Digest(224));
                    break;
                case "SHA3-256WITHDDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(new Sha3Digest(256))), new Sha3Digest(256));
                    break;
                case "SHA3-384WITHDDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(new Sha3Digest(384))), new Sha3Digest(384));
                    break;
                case "SHA3-512WITHDDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(new Sha3Digest(512))), new Sha3Digest(512));
                    break;
                case "MD5WITHDSA":
                    _signer = new DsaDigestSigner(new DsaSigner(), new MD5Digest());
                    break;
                default:
                    _signer = SignerUtilities.GetSigner(jcaSignatureAlgorithm);
                    break;
            }
        }

        public override void InitVerify(PublicKey publicKey)
        {
            if (!(publicKey is BouncyCastlePublicKey bouncyPublic))
            {
                throw new ArgumentException("Need bouncy castle public key");
            }

            _signer.Init(false, bouncyPublic.KeyParameter);
        }

        public override void InitSign(PrivateKey privateKey)
        {
            if (!(privateKey is BouncyCastlePrivateKey bouncyPrivate))
            {
                throw new ArgumentException("Need bouncy castle public key");
            }

            _signer.Init(true, bouncyPrivate.KeyParameter);
        }

        public override void SetParameter(AlgorithmParameterSpec signatureAlgorithmParams)
        {
            // Ignore
        }

        public override void Update(byte data)
        {
            _signer.Update(data);
        }

        public override void Update(ByteBuffer data)
        {
            if (data.HasArray())
            {
                _signer.BlockUpdate(data.Array(), data.ArrayOffset() + data.Position(),
                    data.Limit() - data.Position());
            }
            else
            {
                throw new InvalidOperationException("ByteBuffer without array");
            }
        }

        public override void Update(byte[] data)
        {
            _signer.BlockUpdate(data, 0, data.Length);
        }

        public override bool Verify(byte[] signature)
        {
            return _signer.VerifySignature(signature);
        }

        public override byte[] Sign()
        {
            return _signer.GenerateSignature();
        }
    }
}
