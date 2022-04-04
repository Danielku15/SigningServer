using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography.X509Certificates;
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
            return new PrivateKey(new X509Certificate2(encoded).PrivateKey);
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