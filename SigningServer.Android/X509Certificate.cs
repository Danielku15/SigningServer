using System;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Android
{
    public class X509Certificate
    {
        private X509Certificate2 _certificate;

        public X509Certificate(byte[] encoded)
        {
            _certificate = new X509Certificate2(encoded);
        }

        public X509Certificate(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }
        public X509Certificate()
        {
        }

        public X500Principal getIssuerX500Principal()
        {
            throw new NotImplementedException();
        }


        public byte[] getEncoded()
        {
            // TODO: check for correctness
            return _certificate.Export(X509ContentType.Cert);
        }

        public BigInteger getSerialNumber()
        {
            // TODO 
            return new BigInteger(_certificate.GetSerialNumber());
        }

        public override bool Equals(object obj)
        {
            return base.Equals(obj);
        }

        public PublicKey getPublicKey()
        {
            throw new NotImplementedException();
        }

        public bool hasUnsupportedCriticalExtension()
        {
            throw new NotImplementedException();
        }

        public bool[] getKeyUsage()
        {
            throw new NotImplementedException();
        }

        public X500Principal getSubjectDN()
        {
            throw new NotImplementedException();
        }

        public X500Principal getIssuerDN()
        {
            throw new NotImplementedException();
        }
    }

    public class X500Principal
    {
        public X500Principal(byte[] encodedIssuer)
        {
            throw new System.NotImplementedException();
        }

        public ByteBuffer getEncoded()
        {
            throw new System.NotImplementedException();
        }

        public override bool Equals(object obj)
        {
            return base.Equals(obj);
        }
    }

    public class PrivateKey
    {
    }

    public class PublicKey
    {
        public byte[] getEncoded()
        {
            throw new System.NotImplementedException();
        }

        public string getAlgorithm()
        {
            throw new System.NotImplementedException();
        }

        public static PublicKey FromEncoded(string keyAlgorithm, byte[] publicKeyBytes)
        {
            throw new NotImplementedException();
        }
    }
    public class RSAKey : PublicKey
    {
        public BigInteger getModulus()
        {
            throw new NotImplementedException();
        }
    }
    public class ECKey : PublicKey
    {
        public ECParameterSpec getParams()
        {
            throw new NotImplementedException();
        }
    }

    public class ECParameterSpec
    {
        public BigInteger getOrder()
        {
            
        }
    }

    public class DelegatingX509Certificate : X509Certificate
    {
        private readonly X509Certificate mDelegate;

        public DelegatingX509Certificate(byte[] encoded) : base(encoded)
        {
        }

        public DelegatingX509Certificate(X509Certificate @delegate)
        {
            mDelegate = @delegate;
        }
    }

    public class GuaranteedEncodedFormX509Certificate : DelegatingX509Certificate
    {
        public GuaranteedEncodedFormX509Certificate(X509Certificate @delegate, byte[] encoded)
            : base(@delegate)
        {
        }
    }
}