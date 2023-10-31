using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using NUnit.Framework;
using Org.BouncyCastle.Pkcs;
using SigningServer.Android.Security;
using SigningServer.Android.Security.BouncyCastle;
using SigningServer.Android.Security.DotNet;
using PublicKey = SigningServer.Android.Security.PublicKey;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SigningServer.Android.Runtime.Tests;

[SetUpFixture]
public class BouncyAndDotNetCompatibilityTestData
{
    // NOTE: we know from SigningServer.Android.ApkSig.Tests that the bouncycastle crypto implementation
    // is correct, but we do not have such an extensive test suite for the DotNet implementation 
    // this test suite ensures that the main cryptography operations are the same in the .net and the
    // BouncyCastle implementations

    // due to the indeterministic nature of DSA/ECdsa we focus here on RSA compat

    public static X509Certificate BouncyRsaCertificate { get; private set; }
    public static X509Certificate2 DotNetRsaCertificate { get; private set; }
    public static PrivateKey BouncyRsaPrivateKey { get; private set; }
    public static PrivateKey DotNetRsaPrivateKey { get; private set; }
    public static PublicKey BouncyRsaPublicKey { get; private set; }
    public static PublicKey DotNetRsaPublicKey { get; private set; }

    public static X509Certificate BouncyDsaCertificate { get; private set; }
    public static X509Certificate2 DotNetDsaCertificate { get; private set; }
    public static PrivateKey BouncyDsaPrivateKey { get; private set; }
    public static PrivateKey DotNetDsaPrivateKey { get; private set; }
    public static PublicKey BouncyDsaPublicKey { get; private set; }
    public static PublicKey DotNetDsaPublicKey { get; private set; }

    public static X509Certificate BouncyECDsaCertificate { get; private set; }
    public static X509Certificate2 DotNetECDsaCertificate { get; private set; }
    public static PrivateKey BouncyECDsaPrivateKey { get; private set; }
    public static PrivateKey DotNetECDsaPrivateKey { get; private set; }
    public static PublicKey BouncyECDsaPublicKey { get; private set; }
    public static PublicKey DotNetECDsaPublicKey { get; private set; }

    [OneTimeSetUp]
    public static void SetUp()
    {
        var rsaCert = LoadCertBytes("rsa.pfx");
        var dsaCert = LoadCertBytes("dsa.pfx");
        var ecdsaCert = LoadCertBytes("ecdsa.pfx");

        var rsaDotNet = new X509Certificate2(rsaCert);
        rsaDotNet.HasPrivateKey.Should().BeTrue();
        DotNetRsaCertificate = rsaDotNet;
        DotNetRsaPublicKey = DotNetCryptographyProvider.Instance.CreatePublicKey(rsaDotNet);
        DotNetRsaPrivateKey = DotNetCryptographyProvider.Instance.CreatePrivateKey(rsaDotNet.GetPrivateKey());

        var storeBuilder = new Pkcs12StoreBuilder();
        
        var rsaBouncy = storeBuilder.Build();
        rsaBouncy.Load(new MemoryStream(rsaCert), Array.Empty<char>());
        var alias = rsaBouncy.Aliases.OfType<string>().First();
        BouncyRsaCertificate = rsaBouncy.GetCertificate(alias).Certificate;
        BouncyRsaPublicKey =
            BouncyCastleCryptographyProvider.Instance.CreatePublicKey(BouncyRsaCertificate);
        BouncyRsaPrivateKey =
            BouncyCastleCryptographyProvider.Instance.CreatePrivateKey(rsaBouncy.GetKey(alias).Key);

        var dsaDotNet = new X509Certificate2(dsaCert);
        dsaDotNet.HasPrivateKey.Should().BeTrue();
        DotNetDsaCertificate = dsaDotNet;
        DotNetDsaPublicKey = DotNetCryptographyProvider.Instance.CreatePublicKey(dsaDotNet);
        DotNetDsaPrivateKey = DotNetCryptographyProvider.Instance.CreatePrivateKey(dsaDotNet.GetPrivateKey());

        var dsaBouncy = storeBuilder.Build();
        dsaBouncy.Load(new MemoryStream(dsaCert), Array.Empty<char>());
        alias = dsaBouncy.Aliases.OfType<string>().First();
        BouncyDsaCertificate = dsaBouncy.GetCertificate(alias).Certificate;
        BouncyDsaPublicKey =
            BouncyCastleCryptographyProvider.Instance.CreatePublicKey(BouncyDsaCertificate);
        BouncyDsaPrivateKey =
            BouncyCastleCryptographyProvider.Instance.CreatePrivateKey(dsaBouncy.GetKey(alias).Key);

        var ecdsaDotNet = new X509Certificate2(ecdsaCert);
        ecdsaDotNet.HasPrivateKey.Should().BeTrue();
        DotNetECDsaCertificate = ecdsaDotNet;
        DotNetECDsaPublicKey = DotNetCryptographyProvider.Instance.CreatePublicKey(ecdsaDotNet);
        DotNetECDsaPrivateKey = DotNetCryptographyProvider.Instance.CreatePrivateKey(ecdsaDotNet.GetPrivateKey());

        var ecdsaBouncy = storeBuilder.Build();
        ecdsaBouncy.Load(new MemoryStream(ecdsaCert), Array.Empty<char>());
        alias = ecdsaBouncy.Aliases.OfType<string>().First();
        BouncyECDsaCertificate = ecdsaBouncy.GetCertificate(alias).Certificate;
        BouncyECDsaPublicKey =
            BouncyCastleCryptographyProvider.Instance.CreatePublicKey(BouncyECDsaCertificate);
        BouncyECDsaPrivateKey =
            BouncyCastleCryptographyProvider.Instance.CreatePrivateKey(ecdsaBouncy.GetKey(alias).Key);
    }

    private static byte[] LoadCertBytes(string resourceName)
    {
        var asm = typeof(BouncyAndDotNetCompatibilityTestData).Assembly;
        var name = asm.GetManifestResourceNames().First(n => n.EndsWith("Certificates." + resourceName));
        using var ms = new MemoryStream();
        using var r = typeof(BouncyAndDotNetCompatibilityTestData).Assembly.GetManifestResourceStream(name);
        r.CopyTo(ms);
        return ms.ToArray();
    }
}
