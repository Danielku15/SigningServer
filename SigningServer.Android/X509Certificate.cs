using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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
            return new X500Principal(_certificate.IssuerName);
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
                case RSA _:
                    return new RSAKey(_certificate);
                case ECDsa _:
                    return new RSAKey(_certificate);
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
                throw new CryptographicException("Certificate has no key usage specified");
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
            return new X500Principal(_certificate.SubjectName);
        }

        public X500Principal getIssuerDN()
        {
            return new X500Principal(_certificate.IssuerName);
        }

        public static List<X509Certificate> generateCertificates(byte[] encodedCerts)
        {
            // TODO: support multiple certificates (seems API was only added in .net 5)
            var certificate = new WrappedX509Certificate(encodedCerts);
            return new List<X509Certificate>
            {
                certificate
            };
        }
    }

    public class X500Principal
    {
        private readonly byte[] mEncodedIssuer;
        private readonly X500DistinguishedName mCertificateIssuerName;

        public X500Principal(byte[] encodedIssuer)
        {
            mEncodedIssuer = encodedIssuer;
            mCertificateIssuerName = new X500DistinguishedName(encodedIssuer);
        }

        public X500Principal(X500DistinguishedName certificateIssuerName)
        {
            mCertificateIssuerName = certificateIssuerName;
        }

        public ByteBuffer getEncoded()
        {
            var raw = mEncodedIssuer ?? mCertificateIssuerName.RawData;
            return new ByteBuffer(raw, 0, raw.Length);
        }

        protected bool Equals(X500Principal other)
        {
            return mCertificateIssuerName.Name.Equals(other.mCertificateIssuerName.Name)
                   && mCertificateIssuerName.Oid.Equals(other.mCertificateIssuerName.Oid);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((X500Principal)obj);
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
                    throw new ArgumentException("Unsupported signature algorithm");
            }
        }
    }

    public abstract class PublicKey
    {
        public abstract byte[] getEncoded();
        public abstract string getAlgorithm();

        public static PublicKey FromEncoded(string keyAlgorithm, byte[] publicKeyBytes)
        {
            switch (keyAlgorithm)
            {
                case "RSA":
                    return new RSAKey(publicKeyBytes);
                case "EC":
                    return new ECKey(publicKeyBytes);
            }

            throw new CryptographicException("Unsupported key algorithm : " + keyAlgorithm);
        }

        public abstract bool verify(byte[] signedData, byte[] signature, string jcaSignatureAlgorithm);
    }

    public class RSAKey : PublicKey
    {
        private readonly byte[] mKeyBytes;
        private readonly X509Certificate2 _certificate;

        public RSAKey(byte[] keyBytes)
        {
            mKeyBytes = keyBytes;
            _certificate = new X509Certificate2(keyBytes);
        }


        public RSAKey(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        public override byte[] getEncoded()
        {
            return mKeyBytes ?? _certificate.Export(X509ContentType.Cert);
        }

        public override string getAlgorithm()
        {
            return "RSA";
        }

        public BigInteger getModulus()
        {
            var parameters = _certificate.GetRSAPublicKey().ExportParameters(false);
            return new BigInteger(parameters.Modulus);
        }

        public override bool verify(byte[] signedData, byte[] signature, string jcaSignatureAlgorithm)
        {
            HashAlgorithmName hashAlgorithmName;
            RSASignaturePadding padding;
            switch (jcaSignatureAlgorithm)
            {
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


            return _certificate.GetRSAPublicKey().VerifyData(signedData, signature, hashAlgorithmName, padding);
        }
    }

    public class ECKey : PublicKey
    {
        private readonly byte[] mKeyBytes;
        private readonly X509Certificate2 _certificate;

        public ECKey(byte[] keyBytes)
        {
            mKeyBytes = keyBytes;
            _certificate = new X509Certificate2(keyBytes);
        }

        public ECKey(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        public override string getAlgorithm()
        {
            return "EC";
        }

        public override byte[] getEncoded()
        {
            return mKeyBytes ?? _certificate.Export(X509ContentType.Cert);
        }

        public ECParameterSpec getParams()
        {
            var p = _certificate.GetECDsaPublicKey().ExportParameters(false);
            return new ECParameterSpec(p);
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


            return _certificate.GetECDsaPublicKey().VerifyData(signedData, signature, hashAlgorithmName);
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