using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Pkcs;
using SigningServer.Android.Security;
using SigningServer.Android.Security.BouncyCastle;
using SigningServer.Android.Security.DotNet;
using PublicKey = SigningServer.Android.Security.PublicKey;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SigningServer.Android
{
    [TestClass]
    public class BouncyAndDotNetCompatibilityTestData
    {
        // NOTE: we know from SigningServer.Android.ApkSig.Test that the bouncycastle crypto implementation
        // is correct, but we do not have such an extensive test suite for the DotNet implementation 
        // this test suite ensures that the main cryptography operations are the same in the .net and the
        // BouncyCastle implementations

        // due to the indeterministic nature of DSA/ECdsa we focus here on RSA compat

        public static X509Certificate BouncyRsaCertificate;
        public static X509Certificate2 DotNetRsaCertificate;
        public static PrivateKey BouncyRsaPrivateKey;
        public static PrivateKey DotNetRsaPrivateKey;
        public static PublicKey BouncyRsaPublicKey;
        public static PublicKey DotNetRsaPublicKey;

        public static X509Certificate BouncyDsaCertificate;
        public static X509Certificate2 DotNetDsaCertificate;
        public static PrivateKey BouncyDsaPrivateKey;
        public static PrivateKey DotNetDsaPrivateKey;
        public static PublicKey BouncyDsaPublicKey;
        public static PublicKey DotNetDsaPublicKey;

        public static X509Certificate BouncyECDsaCertificate;
        public static X509Certificate2 DotNetECDsaCertificate;
        public static PrivateKey BouncyECDsaPrivateKey;
        public static PrivateKey DotNetECDsaPrivateKey;
        public static PublicKey BouncyECDsaPublicKey;
        public static PublicKey DotNetECDsaPublicKey;

        [AssemblyInitialize]
        public static void SetUp(TestContext context)
        {
            var rsaCert = LoadCertBytes("rsa.pfx");
            var dsaCert = LoadCertBytes("dsa.pfx");
            var ecdsaCert = LoadCertBytes("ecdsa.pfx");

            var rsaDotNet = new X509Certificate2(rsaCert);
            rsaDotNet.HasPrivateKey.Should().BeTrue();
            DotNetRsaCertificate = rsaDotNet;
            DotNetRsaPublicKey = DotNetCryptographyProvider.INSTANCE.CreatePublicKey(rsaDotNet);
            DotNetRsaPrivateKey = DotNetCryptographyProvider.INSTANCE.CreatePrivateKey(rsaDotNet);

            var rsaBouncy = new Pkcs12Store(new MemoryStream(rsaCert), Array.Empty<char>());
            var alias = rsaBouncy.Aliases.OfType<string>().First();
            BouncyRsaCertificate = rsaBouncy.GetCertificate(alias).Certificate;
            BouncyRsaPublicKey =
                BouncyCastleCryptographyProvider.INSTANCE.CreatePublicKey(BouncyRsaCertificate);
            BouncyRsaPrivateKey =
                BouncyCastleCryptographyProvider.INSTANCE.CreatePrivateKey(rsaBouncy.GetKey(alias).Key);

            var dsaDotNet = new X509Certificate2(dsaCert);
            dsaDotNet.HasPrivateKey.Should().BeTrue();
            DotNetDsaCertificate = dsaDotNet;
            DotNetDsaPublicKey = DotNetCryptographyProvider.INSTANCE.CreatePublicKey(dsaDotNet);
            DotNetDsaPrivateKey = DotNetCryptographyProvider.INSTANCE.CreatePrivateKey(dsaDotNet);

            var dsaBouncy = new Pkcs12Store(new MemoryStream(dsaCert), Array.Empty<char>());
            alias = dsaBouncy.Aliases.OfType<string>().First();
            BouncyDsaCertificate = dsaBouncy.GetCertificate(alias).Certificate;
            BouncyDsaPublicKey =
                BouncyCastleCryptographyProvider.INSTANCE.CreatePublicKey(BouncyDsaCertificate);
            BouncyDsaPrivateKey =
                BouncyCastleCryptographyProvider.INSTANCE.CreatePrivateKey(dsaBouncy.GetKey(alias).Key);

            var ecdsaDotNet = new X509Certificate2(ecdsaCert);
            ecdsaDotNet.HasPrivateKey.Should().BeTrue();
            DotNetECDsaCertificate = ecdsaDotNet;
            DotNetECDsaPublicKey = DotNetCryptographyProvider.INSTANCE.CreatePublicKey(ecdsaDotNet);
            DotNetECDsaPrivateKey = DotNetCryptographyProvider.INSTANCE.CreatePrivateKey(ecdsaDotNet);

            var ecdsaBouncy = new Pkcs12Store(new MemoryStream(ecdsaCert), Array.Empty<char>());
            alias = ecdsaBouncy.Aliases.OfType<string>().First();
            BouncyECDsaCertificate = ecdsaBouncy.GetCertificate(alias).Certificate;
            BouncyECDsaPublicKey =
                BouncyCastleCryptographyProvider.INSTANCE.CreatePublicKey(BouncyECDsaCertificate);
            BouncyECDsaPrivateKey =
                BouncyCastleCryptographyProvider.INSTANCE.CreatePrivateKey(ecdsaBouncy.GetKey(alias).Key);
        }

        private static byte[] LoadCertBytes(string resourceName)
        {
            using (var ms = new MemoryStream())
            using (var r = typeof(BouncyAndDotNetCompatibilityTestData).Assembly.GetManifestResourceStream(
                       "SigningServer.Android.Certificates." + resourceName))
            {
                r.CopyTo(ms);
                return ms.ToArray();
            }
        }
    }
}