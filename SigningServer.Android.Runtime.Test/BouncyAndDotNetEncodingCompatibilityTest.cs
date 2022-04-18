using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.Security.BouncyCastle;
using SigningServer.Android.Security.DotNet;

namespace SigningServer.Android.Runtime.Test;

[TestClass]
public class BouncyAndDotNetEncodingCompatibilityTest
{
    [TestMethod]
    public void RsaCert()
    {
        var bouncy = BouncyCastleCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyRsaCertificate);
        var dotNet = DotNetCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetRsaCertificate);
        dotNet.GetEncoded().Should().Equal(bouncy.GetEncoded());
    }

    [TestMethod]
    public void DsaCert()
    {
        var bouncy = BouncyCastleCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyDsaCertificate);
        var dotNet = DotNetCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetDsaCertificate);
        dotNet.GetEncoded().Should().Equal(bouncy.GetEncoded());
    }

    [TestMethod]
    public void ECDsaCert()
    {
        var bouncy = BouncyCastleCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyECDsaCertificate);
        var dotNet = DotNetCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetECDsaCertificate);
        dotNet.GetEncoded().Should().Equal(bouncy.GetEncoded());
    }
        
    [TestMethod]
    public void RsaPublicKey()
    {
        var bouncy = BouncyAndDotNetCompatibilityTestData.BouncyRsaPublicKey;
        var dotNet = BouncyAndDotNetCompatibilityTestData.DotNetRsaPublicKey;
        dotNet.GetEncoded().Should().Equal(bouncy.GetEncoded());
    }

    [TestMethod]
    public void DsaPublicKey()
    {
        var bouncy = BouncyAndDotNetCompatibilityTestData.BouncyDsaPublicKey;
        var dotNet = BouncyAndDotNetCompatibilityTestData.DotNetDsaPublicKey;
        dotNet.GetEncoded().Should().Equal(bouncy.GetEncoded());
    }

    [TestMethod]
    public void ECDsaPublicKey()
    {
        var bouncy = BouncyAndDotNetCompatibilityTestData.BouncyECDsaPublicKey;
        var dotNet = BouncyAndDotNetCompatibilityTestData.DotNetECDsaPublicKey;
        dotNet.GetEncoded().Should().Equal(bouncy.GetEncoded());
    }
        
    [TestMethod]
    public void RsaSerialNumber()
    {
        var bouncy = BouncyCastleCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyRsaCertificate);
        var dotNet = DotNetCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetRsaCertificate);
        dotNet.GetSerialNumber().Should().Be(bouncy.GetSerialNumber());
    }

    [TestMethod]
    public void DsaSerialNumber()
    {
        var bouncy = BouncyCastleCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyDsaCertificate);
        var dotNet = DotNetCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetDsaCertificate);
        dotNet.GetSerialNumber().Should().Be(bouncy.GetSerialNumber());
    }

    [TestMethod]
    public void ECDsaSerialNumber()
    {
        var bouncy = BouncyCastleCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyECDsaCertificate);
        var dotNet = DotNetCryptographyProvider.Instance.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetECDsaCertificate);
        dotNet.GetSerialNumber().Should().Be(bouncy.GetSerialNumber());
    }
}