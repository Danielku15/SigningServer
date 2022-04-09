using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SigningServer.Android.ApkSig;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Internal.X509;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.Test.ApkSig.Internal.Util
{
    public class Resources
    {
        public static byte[] toByteArray(String resourceName)
        {
            using (Stream @in =
                   typeof(Resources).Assembly.GetManifestResourceStream("SigningServer.Android.Test.Resources." +
                                                                        resourceName))
            {
                if (@in == null)
                {
                    throw new ArgumentException("Resource not found: " + resourceName);
                }

                return ByteStreams.toByteArray(@in);
            }
        }

        public static Stream toInputStream(String resourceName)
        {
            Stream @in = typeof(Resources).Assembly.GetManifestResourceStream("SigningServer.Android.Test.Resources." +
                                                                resourceName);
            if (@in == null)
            {
                throw new ArgumentException("Resource not found: " + resourceName);
            }

            return @in;
        }

        public static X509Certificate toCertificate(
            String resourceName)
        {
            using (Stream @in = typeof(Resources).Assembly.GetManifestResourceStream("SigningServer.Android.Test.Resources." +
                       resourceName))
            {
                if (@in == null)
                {
                    throw new ArgumentException("Resource not found: " + resourceName);
                }

                return X509CertificateUtils.generateCertificate(@in);
            }
        }

        public static List<X509Certificate> toCertificateChain(String resourceName)
        {
            List<X509Certificate> certs;
            using (Stream @in = typeof(Resources).Assembly.GetManifestResourceStream("SigningServer.Android.Test.Resources." +
                       resourceName))
            {
                if (@in == null)
                {
                    throw new ArgumentException("Resource not found: " + resourceName);
                }

                certs = X509CertificateUtils.generateCertificates(@in);
            }

            return certs;
        }

        public static PrivateKey toPrivateKey(String resourceName)
        {
            int delimiterIndex = resourceName.IndexOf('-');
            if (delimiterIndex == -1)
            {
                throw new ArgumentException(
                    "Failed to autodetect key algorithm from resource name: " + resourceName);
            }

            String keyAlgorithm = resourceName.Substring(0, delimiterIndex).ToUpperInvariant();
            return toPrivateKey(resourceName, keyAlgorithm);
        }

        public static PrivateKey toPrivateKey(string resourceName, String keyAlgorithm)
        {
            byte[] encoded = toByteArray(resourceName);
            var key = PrivateKeyFactory.CreateKey(encoded);

            switch (keyAlgorithm)
            {
                case "RSA":
                    return new PrivateKey(DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)key));
                case "DSA":
                    var dsaKeyParameters = (DsaPrivateKeyParameters)key;
                    DSACryptoServiceProvider dsa = new DSACryptoServiceProvider();
                    dsa.ImportParameters(new DSAParameters
                    {
                        Counter = dsaKeyParameters.Parameters.ValidationParameters?.Counter ?? 0,
                        P = dsaKeyParameters.Parameters.P.ToByteArray(),
                        Q = dsaKeyParameters.Parameters.Q.ToByteArray(),
                        G = dsaKeyParameters.Parameters.G.ToByteArray(),
                        // J = dsaKeyParameters.,
                        Seed = dsaKeyParameters.Parameters.ValidationParameters?.GetSeed(),
                        X = dsaKeyParameters.X.ToByteArray(),
                        // Y = dsaKeyParameters.
                    });
                    return new PrivateKey(dsa);
                // case "EC":
                //     var ecKeyParameters = (ECPrivateKeyParameters)factory;
                //     var ecProvider = new ECDsaCng();
                //     ecProvider.ImportParameters(new ECParameters
                //     {
                //         D = ecKeyParameters.D.ToByteArray(),
                //         Curve = new ECCurve
                //         {
                //             A = ecKeyParameters.Parameters.Curve.A.GetEncoded(),
                //             B = ecKeyParameters.Parameters.Curve.B.GetEncoded(),
                //             Cofactor = ecKeyParameters.Parameters.Curve.Cofactor.ToByteArray(),
                //             G = new ECPoint
                //             {
                //                 X = ecKeyParameters.Parameters.G.XCoord.GetEncoded(),
                //                 Y = ecKeyParameters.Parameters.G.YCoord.GetEncoded()
                //             },
                //             Order = ecKeyParameters.Parameters.Curve.Order.ToByteArray(),
                //             Polynomial = ecKeyParameters.Parameters.Curve..ToByteArray()
                //         }
                //     });
                //     return new PrivateKey(ecProvider);
            }
            
            throw new CryptographicException("Unsupported algorithm: " + keyAlgorithm);
        }
        
        public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
            rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
            rp.P = privKey.P.ToByteArrayUnsigned();
            rp.Q = privKey.Q.ToByteArrayUnsigned();
            rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
            rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
            rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
            rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);
            return rp;
        }

        private static byte[] ConvertRSAParametersField(Org.BouncyCastle.Math.BigInteger n, int size)
        {
            byte[] bs = n.ToByteArrayUnsigned();
            if (bs.Length == size)
                return bs;
            if (bs.Length > size)
                throw new ArgumentException("Specified size too small", "size");
            byte[] padded = new byte[size];
            Array.Copy(bs, 0, padded, size - bs.Length, bs.Length);
            return padded;
        }


        public static SigningCertificateLineage.SignerConfig toLineageSignerConfig(String resourcePrefix)
        {
            PrivateKey privateKey = toPrivateKey(resourcePrefix + ".pk8");
            X509Certificate cert = Resources.toCertificate(resourcePrefix + ".x509.pem");
            return new SigningCertificateLineage.SignerConfig.Builder(privateKey, cert).build();
        }

        public static DataSource toDataSource(String dataSourceResourceName)
        {
            return new ByteBufferDataSource(ByteBuffer.wrap(Resources
                .toByteArray(dataSourceResourceName)));
        }

        public static SigningCertificateLineage toSigningCertificateLineage(String fileResourceName)
        {
            DataSource lineageDataSource = toDataSource(fileResourceName);
            return SigningCertificateLineage.readFromDataSource(lineageDataSource);
        }
    }
}