// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;
using SigningServer.Android.IO;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    /// <summary>
    /// Assorted methods to obtaining test input from resources.
    /// </summary>
    public class Resources: SigningServer.Android.TestBase
    {
        internal Resources()
        {
        }
        
        public static byte[] ToByteArray(Type cls, string resourceName)
        {
            using(SigningServer.Android.IO.InputStream input = GetResourceAsStream(cls, resourceName))
            {
                if (input == null)
                {
                    throw new System.ArgumentException("Resource not found: " + resourceName);
                }
                return Com.Android.Apksig.Internal.Util.ByteStreams.ToByteArray(input);
            }
        }

        private static InputStream GetResourceAsStream(Type cls, string resourceName)
        {
            var relativeNs = cls.Namespace.Replace(
                "SigningServer.Android.Com.Android.Apksig",
                "SigningServer.Android.Resources");

            var fullName = relativeNs + "." + resourceName;
            var stream = typeof(Resources).Assembly.GetManifestResourceStream(fullName);
            return stream != null ? new WrapperInputStream(stream) : null;
        }

        public static SigningServer.Android.IO.InputStream ToInputStream(System.Type cls, string resourceName)
        {
            SigningServer.Android.IO.InputStream input = GetResourceAsStream(cls, resourceName);
            if (input == null)
            {
                throw new System.ArgumentException("Resource not found: " + resourceName);
            }
            return input;
        }
        
        public static SigningServer.Android.Security.Cert.X509Certificate ToCertificate(System.Type cls, string resourceName)
        {
            using(SigningServer.Android.IO.InputStream input = GetResourceAsStream(cls, resourceName))
            {
                if (input == null)
                {
                    throw new System.ArgumentException("Resource not found: " + resourceName);
                }
                return Com.Android.Apksig.Internal.Util.X509CertificateUtils.GenerateCertificate(input);
            }
        }
        
        public static SigningServer.Android.Collections.List<SigningServer.Android.Security.Cert.X509Certificate> ToCertificateChain(System.Type cls, string resourceName)
        {
            SigningServer.Android.Collections.Collection<SigningServer.Android.Security.Cert.Certificate> certs;
            using(SigningServer.Android.IO.InputStream input = GetResourceAsStream(cls, resourceName))
            {
                if (input == null)
                {
                    throw new System.ArgumentException("Resource not found: " + resourceName);
                }
                certs = Com.Android.Apksig.Internal.Util.X509CertificateUtils.GenerateCertificates(input);
            }
            SigningServer.Android.Collections.List<SigningServer.Android.Security.Cert.X509Certificate> result = new SigningServer.Android.Collections.List<SigningServer.Android.Security.Cert.X509Certificate>(certs.Size());
            foreach (SigningServer.Android.Security.Cert.Certificate cert in certs)
            {
                result.Add((SigningServer.Android.Security.Cert.X509Certificate)cert);
            }
            return result;
        }
        
        public static SigningServer.Android.Security.PrivateKey ToPrivateKey(System.Type cls, string resourceName)
        {
            int delimiterIndex = resourceName.IndexOf('-');
            if (delimiterIndex == -1)
            {
                throw new System.ArgumentException("Failed to autodetect key algorithm from resource name: " + resourceName);
            }
            string keyAlgorithm = resourceName.Substring(0, delimiterIndex).ToUpperCase(SigningServer.Android.Util.Locale.US);
            return SigningServer.Android.Com.Android.Apksig.Internal.Util.Resources.ToPrivateKey(cls, resourceName, keyAlgorithm);
        }
        
        public static SigningServer.Android.Security.PrivateKey ToPrivateKey(System.Type cls, string resourceName, string keyAlgorithm)
        {
            byte[] encoded = SigningServer.Android.Com.Android.Apksig.Internal.Util.Resources.ToByteArray(cls, resourceName);
            SigningServer.Android.Security.KeyFactory keyFactory;
            switch (keyAlgorithm.ToUpperCase(SigningServer.Android.Util.Locale.US))
            {
                case "RSA":
                    keyFactory = SigningServer.Android.Security.KeyFactory.GetInstance("rsa");
                    break;
                case "DSA":
                    keyFactory = SigningServer.Android.Security.KeyFactory.GetInstance("dsa");
                    break;
                case "EC":
                    keyFactory = SigningServer.Android.Security.KeyFactory.GetInstance("ec");
                    break;
                default:
                    throw new SigningServer.Android.Security.Spec.InvalidKeySpecException("Unsupported key algorithm: " + keyAlgorithm);
            }
            return keyFactory.GeneratePrivate(new SigningServer.Android.Security.Spec.PKCS8EncodedKeySpec(encoded));
        }
        
        public static Com.Android.Apksig.SigningCertificateLineage.SignerConfig ToLineageSignerConfig(System.Type cls, string resourcePrefix)
        {
            SigningServer.Android.Security.PrivateKey privateKey = SigningServer.Android.Com.Android.Apksig.Internal.Util.Resources.ToPrivateKey(cls, resourcePrefix + ".pk8");
            SigningServer.Android.Security.Cert.X509Certificate cert = SigningServer.Android.Com.Android.Apksig.Internal.Util.Resources.ToCertificate(cls, resourcePrefix + ".x509.pem");
            return new Com.Android.Apksig.SigningCertificateLineage.SignerConfig.Builder(privateKey, cert).Build();
        }
        
        public static Com.Android.Apksig.Util.DataSource ToDataSource(System.Type cls, string dataSourceResourceName)
        {
            return new Com.Android.Apksig.Internal.Util.ByteBufferDataSource(SigningServer.Android.IO.ByteBuffer.Wrap(SigningServer.Android.Com.Android.Apksig.Internal.Util.Resources.ToByteArray(typeof(SigningServer.Android.Com.Android.Apksig.ApkSignerTest), dataSourceResourceName)));
        }
        
        public static Com.Android.Apksig.SigningCertificateLineage ToSigningCertificateLineage(System.Type cls, string fileResourceName)
        {
            Com.Android.Apksig.Util.DataSource lineageDataSource = SigningServer.Android.Com.Android.Apksig.Internal.Util.Resources.ToDataSource(cls, fileResourceName);
            return Com.Android.Apksig.SigningCertificateLineage.ReadFromDataSource(lineageDataSource);
        }
        
    }
    
}
