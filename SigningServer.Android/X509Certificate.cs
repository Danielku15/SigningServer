using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace SigningServer.Android
{
    public interface X509Certificate
    {
        X500Principal getIssuerX500Principal();
        byte[] getEncoded();
        BigInteger getSerialNumber();
        PublicKey getPublicKey();
        bool hasUnsupportedCriticalExtension();
        bool[] getKeyUsage();
        X500Principal getSubjectDN();
        X500Principal getIssuerDN();
        bool Equals(X509Certificate other);
    }

    public class WrappedX509Certificate : X509Certificate
    {
        private readonly byte[] mEncoded;
        private X509Certificate2 _certificate;

        public WrappedX509Certificate(byte[] encoded)
        {
            if (encoded.Length == 0)
            {
                throw new CryptographicException("Invalid certificate data");
            }

            mEncoded = encoded;
            _certificate = new X509Certificate2(encoded);
        }

        public WrappedX509Certificate(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        public WrappedX509Certificate()
        {
        }

        public X500Principal getIssuerX500Principal()
        {
            return new WrappedX500Principal(_certificate.IssuerName);
        }


        public byte[] getEncoded()
        {
            // TODO: check for correctness
            return mEncoded ?? _certificate.Export(X509ContentType.Cert);
        }

        public BigInteger getSerialNumber()
        {
            // TODO check for correctness
            return new BigInteger(_certificate.GetSerialNumber());
        }

        public bool Equals(X509Certificate other)
        {
            return getEncoded().SequenceEqual(other.getEncoded());
        }

        public PublicKey getPublicKey()
        {
            switch (_certificate.PublicKey.Key)
            {
                case DSA dsa:
                    return new DSAKey(null, _certificate.PublicKey, dsa);
                case RSA rsa:
                    return new RSAKey(null, _certificate.PublicKey, rsa);
                case ECDsa ec:
                    return new ECKey(null, _certificate.PublicKey, ec);
            }

            throw new CryptographicException("Unsupported public key type");
        }

        public bool hasUnsupportedCriticalExtension()
        {
            return false;
        }

        public bool[] getKeyUsage()
        {
            var keyUsage = _certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsage == null)
            {
                return null;
            }

            return new[]
            {
                keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature),
                keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation),
                keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment),
                keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DataEncipherment),
                keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyAgreement),
                keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign),
                keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign),
                keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.EncipherOnly),
                keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DecipherOnly)
            };
        }

        public X500Principal getSubjectDN()
        {
            return new WrappedX500Principal(_certificate.SubjectName);
        }

        public X500Principal getIssuerDN()
        {
            return new WrappedX500Principal(_certificate.IssuerName);
        }
    }

    public interface X500Principal : IEquatable<X500Principal>
    {
        ByteBuffer getEncoded();
        string getName();
        Oid getOid();
    }

    public class WrappedX500Principal : X500Principal
    {
        private readonly byte[] mEncodedIssuer;
        private readonly X500DistinguishedName mCertificateIssuerName;

        public WrappedX500Principal(byte[] encodedIssuer)
        {
            mEncodedIssuer = encodedIssuer;
            mCertificateIssuerName = new X500DistinguishedName(encodedIssuer);
        }

        public WrappedX500Principal(X500DistinguishedName certificateIssuerName)
        {
            mCertificateIssuerName = certificateIssuerName;
        }

        public ByteBuffer getEncoded()
        {
            var raw = mEncodedIssuer ?? mCertificateIssuerName.RawData;
            return ByteBuffer.wrap(raw, 0, raw.Length);
        }


        public bool Equals(X500Principal other)
        {
            return mCertificateIssuerName.Name.Equals(other.getName())
                   && (ReferenceEquals(mCertificateIssuerName.Oid.Value, other.getOid().Value) ||
                       (mCertificateIssuerName.Oid.Value?.Equals(other.getOid().Value) ?? false));
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (!(obj is X500Principal p)) return false;
            return Equals(p);
        }

        public override int GetHashCode()
        {
            return ((mCertificateIssuerName.Name != null ? mCertificateIssuerName.Name.GetHashCode() : 0) * 397) ^
                   (mCertificateIssuerName.Oid != null ? mCertificateIssuerName.Oid.GetHashCode() : 0);
        }

        public string getName()
        {
            return mCertificateIssuerName.Name;
        }

        public Oid getOid()
        {
            return mCertificateIssuerName.Oid;
        }
    }

    public class PrivateKey
    {
        private AsymmetricAlgorithm mPrivateKey;

        public PrivateKey(AsymmetricAlgorithm privateKey)
        {
            mPrivateKey = privateKey;
        }

        public byte[] sign(byte[] data, string jcaSignatureAlgorithm)
        {
            switch (jcaSignatureAlgorithm)
            {
                case "MD5withRSA":
                    return ((RSA)mPrivateKey).SignData(data, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1);
                case "SHA1withRSA":
                    return ((RSA)mPrivateKey).SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                case "SHA256withRSA/PSS":
                    return ((RSA)mPrivateKey).SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                case "SHA512withRSA/PSS":
                    return ((RSA)mPrivateKey).SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                case "SHA256withRSA":
                    return ((RSA)mPrivateKey).SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                case "SHA512withRSA":
                    return ((RSA)mPrivateKey).SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                case "SHA256withECDSA":
                    return ((ECDsa)mPrivateKey).SignData(data, HashAlgorithmName.SHA256);
                case "SHA512withECDSA":
                    return ((ECDsa)mPrivateKey).SignData(data, HashAlgorithmName.SHA512);
                case "SHA256withDSA":
                    return ((DSA)mPrivateKey).SignData(data, HashAlgorithmName.SHA256);
                default:
                    throw new ArgumentException("Unsupported signature algorithm: " + jcaSignatureAlgorithm);
            }
        }
    }

    public abstract class PublicKey
    {
        public abstract byte[] getEncoded();
        public abstract string getAlgorithm();

        public static PublicKey FromEncoded(string keyAlgorithm, byte[] publicKeyBytes)
        {
            var key = PublicKeyFactory.CreateKey(publicKeyBytes);

            switch (keyAlgorithm)
            {
                case "RSA":
                    var rsaKey = (RsaKeyParameters)key;
                    return new RSAKey(publicKeyBytes,
                        null,
                        DotNetUtilities.ToRSA(rsaKey));
                case "EC":
                    var ecKey = (ECPublicKeyParameters)key;
                    return new ECKey(publicKeyBytes,
                        null,
                        ToECDsa(ecKey));
            }

            throw new CryptographicException("Unsupported key algorithm : " + keyAlgorithm);
        }

        private static ECDsa ToECDsa(ECPublicKeyParameters ecKey)
        {
            var ecDsa = new ECDsaCng();
            ecDsa.ImportParameters(new ECParameters
            {
                Q = new ECPoint
                {
                    X = ecKey.Q.XCoord.GetEncoded(),
                    Y = ecKey.Q.XCoord.GetEncoded()
                },
                Curve = new ECCurve
                {
                    A = ecKey.Parameters.Curve.A.GetEncoded(),
                    B = ecKey.Parameters.Curve.B.GetEncoded(),
                    Cofactor = ecKey.Parameters.Curve.Cofactor.ToByteArray(),
                    G = new ECPoint
                    {
                        X = ecKey.Parameters.G.XCoord.GetEncoded(),
                        Y = ecKey.Parameters.G.YCoord.GetEncoded()
                    },
                    Order = ecKey.Parameters.Curve.Order.ToByteArray(),
                    CurveType = ECCurve.ECCurveType.PrimeTwistedEdwards,
                    // TODO 
                    // Polynomial = ecKey.Parameters.Curve.Field.ToByteArray(),
                    // Polynomial = ecKey.Parameters.Curve.CoordinateSystem.ToByteArray(),
                    // Polynomial = ecKey.Parameters.Curve.FieldSize.ToByteArray(),
                    // CurveType = ecKey.Parameters.Curve.,
                    // Hash = ,
                    // Oid = {  },
                    // Prime = ecKey.Parameters.Curve.,
                    Seed = ecKey.Parameters.GetSeed()
                },
                D = null
            });
            return ecDsa;
        }

        public abstract bool verify(byte[] signedData, byte[] signature, string jcaSignatureAlgorithm);
    }

    public class RSAKey : PublicKey
    {
        private readonly byte[] mKeyBytes;
        private readonly System.Security.Cryptography.X509Certificates.PublicKey mPublicKey;
        private readonly RSA mRsa;
        private readonly RSAParameters mParameters;

        public RSAKey(byte[] keyBytes, System.Security.Cryptography.X509Certificates.PublicKey publicKey, RSA rsa)
        {
            mKeyBytes = keyBytes;
            mPublicKey = publicKey;
            mRsa = rsa;
            mParameters = rsa.ExportParameters(false);
        }

        public override byte[] getEncoded()
        {
            if (mKeyBytes != null)
            {
                return mKeyBytes;
            }

            if (mPublicKey != null)
            {
                var rawKey = mPublicKey.EncodedKeyValue.RawData;

                var sequence = new DerSequence(
                    new DerSequence(new DerObjectIdentifier(mPublicKey.Oid.Value), DerNull.Instance),
                    new DerBitString(rawKey)
                );

                return sequence.GetEncoded();
            }

            return null;
        }

        public override string getAlgorithm()
        {
            return "RSA";
        }

        public BigInteger getModulus()
        {
            return new BigInteger(mParameters.Modulus);
        }

        public override bool verify(byte[] signedData, byte[] signature, string jcaSignatureAlgorithm)
        {
            HashAlgorithmName hashAlgorithmName;
            RSASignaturePadding padding;
            switch (jcaSignatureAlgorithm)
            {
                case "MD5withRSA":
                    hashAlgorithmName = HashAlgorithmName.MD5;
                    padding = RSASignaturePadding.Pkcs1;
                    break;
                case "SHA1withRSA":
                    hashAlgorithmName = HashAlgorithmName.SHA1;
                    padding = RSASignaturePadding.Pkcs1;
                    break;
                case "SHA256withRSA/PSS":
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    padding = RSASignaturePadding.Pss;
                    break;
                case "SHA512withRSA/PSS":
                    hashAlgorithmName = HashAlgorithmName.SHA512;
                    padding = RSASignaturePadding.Pss;
                    break;
                case "SHA256withRSA":
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    padding = RSASignaturePadding.Pkcs1;
                    break;
                case "SHA512withRSA":
                    hashAlgorithmName = HashAlgorithmName.SHA512;
                    padding = RSASignaturePadding.Pkcs1;
                    break;
                default:
                    throw new ArgumentException("Unsupported algorithm");
            }


            return mRsa.VerifyData(signedData, signature, hashAlgorithmName, padding);
        }
    }

    public class DSAKey : PublicKey
    {
        private readonly byte[] mKeyBytes;
        private readonly System.Security.Cryptography.X509Certificates.PublicKey mPublicKey;
        private readonly DSA mDsa;
        private readonly DSAParameters mParameters;

        public DSAKey(byte[] keyBytes, System.Security.Cryptography.X509Certificates.PublicKey publicKey, DSA dsa)
        {
            mKeyBytes = keyBytes;
            mPublicKey = publicKey;
            mDsa = dsa;
            mParameters = dsa.ExportParameters(false);
        }

        public override byte[] getEncoded()
        {
            if (mKeyBytes != null)
            {
                return mKeyBytes;
            }

            if (mPublicKey != null)
            {
                var rawKey = mPublicKey.EncodedKeyValue.RawData;

                var sequence = new DerSequence(
                    new DerSequence(new DerObjectIdentifier(mPublicKey.Oid.Value), DerNull.Instance),
                    new DerBitString(rawKey)
                );

                return sequence.GetEncoded();
            }

            return null;
        }

        public override string getAlgorithm()
        {
            return "RSA";
        }

        public override bool verify(byte[] signedData, byte[] signature, string jcaSignatureAlgorithm)
        {
            HashAlgorithmName hashAlgorithmName;
            switch (jcaSignatureAlgorithm)
            {
                case "MD5withDSA":
                    hashAlgorithmName = HashAlgorithmName.MD5;
                    break;
                case "SHA1withDSA":
                    hashAlgorithmName = HashAlgorithmName.SHA1;
                    break;
                case "SHA256withDSA":
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    break;
                case "SHA512withDSA":
                    hashAlgorithmName = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new ArgumentException("Unsupported algorithm");
            }


            return mDsa.VerifyData(signedData, signature, hashAlgorithmName);
        }
    }

    public class ECKey : PublicKey
    {
        private readonly byte[] mKeyBytes;
        private readonly System.Security.Cryptography.X509Certificates.PublicKey mPublicKey;
        private readonly ECDsa mEC;
        private readonly ECParameters mParameters;

        public ECKey(byte[] keyBytes, System.Security.Cryptography.X509Certificates.PublicKey publicKey, ECDsa ec)
        {
            mKeyBytes = keyBytes;
            mPublicKey = publicKey;
            mEC = ec;
            mParameters = ec.ExportParameters(false);
        }

        public override string getAlgorithm()
        {
            return "EC";
        }

        public override byte[] getEncoded()
        {
            if (mKeyBytes != null)
            {
                return mKeyBytes;
            }

            if (mPublicKey != null)
            {
                var rawKey = mPublicKey.EncodedKeyValue.RawData;

                var sequence = new DerSequence(
                    new DerSequence(new DerObjectIdentifier(mPublicKey.Oid.Value), DerNull.Instance),
                    new DerBitString(rawKey)
                );

                return sequence.GetEncoded();
            }

            return null;
        }

        public ECParameterSpec getParams()
        {
            return new ECParameterSpec(mParameters);
        }

        public override bool verify(byte[] signedData, byte[] signature, string jcaSignatureAlgorithm)
        {
            HashAlgorithmName hashAlgorithmName;
            switch (jcaSignatureAlgorithm)
            {
                case "SHA256withECDSA":
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    break;
                case "SHA512withECDSA":
                    hashAlgorithmName = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new ArgumentException("Unsupported algorithm");
            }


            return mEC.VerifyData(signedData, signature, hashAlgorithmName);
        }
    }

    public class ECParameterSpec
    {
        private readonly ECParameters mEcParameters;

        public ECParameterSpec(ECParameters ecParameters)
        {
            mEcParameters = ecParameters;
        }

        public BigInteger getOrder()
        {
            return new BigInteger(mEcParameters.Curve.Order);
        }
    }

    public class DelegatingX509Certificate : X509Certificate
    {
        private readonly X509Certificate mDelegate;

        public DelegatingX509Certificate(X509Certificate @delegate)
        {
            mDelegate = @delegate;
        }

        public X500Principal getIssuerX500Principal()
        {
            return mDelegate.getIssuerX500Principal();
        }

        public virtual byte[] getEncoded()
        {
            return mDelegate.getEncoded();
        }

        public BigInteger getSerialNumber()
        {
            return mDelegate.getSerialNumber();
        }

        public PublicKey getPublicKey()
        {
            return mDelegate.getPublicKey();
        }

        public bool hasUnsupportedCriticalExtension()
        {
            return mDelegate.hasUnsupportedCriticalExtension();
        }

        public bool[] getKeyUsage()
        {
            return mDelegate.getKeyUsage();
        }

        public X500Principal getSubjectDN()
        {
            return mDelegate.getSubjectDN();
        }

        public X500Principal getIssuerDN()
        {
            return mDelegate.getIssuerDN();
        }

        public bool Equals(X509Certificate other)
        {
            return mDelegate.Equals(other);
        }
    }

    public class GuaranteedEncodedFormX509Certificate : DelegatingX509Certificate
    {
        private readonly byte[] mEncoded;

        public GuaranteedEncodedFormX509Certificate(X509Certificate @delegate, byte[] encoded)
            : base(@delegate)
        {
            mEncoded = encoded;
        }

        public override byte[] getEncoded()
        {
            return mEncoded;
        }
    }
}