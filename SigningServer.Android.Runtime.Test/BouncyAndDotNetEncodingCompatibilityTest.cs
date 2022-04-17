using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.Security.BouncyCastle;
using SigningServer.Android.Security.DotNet;

namespace SigningServer.Android.Runtime.Test
{
    [TestClass]
    public class BouncyAndDotNetEncodingCompatibilityTest
    {
        [TestMethod]
        public void RsaCert()
        {
            var bouncy = BouncyCastleCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyRsaCertificate);
            var dotNet = DotNetCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetRsaCertificate);
            dotNet.GetEncoded().Should().Equal(bouncy.GetEncoded());
        }

        [TestMethod]
        public void DsaCert()
        {
            var bouncy = BouncyCastleCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyDsaCertificate);
            var dotNet = DotNetCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetDsaCertificate);
            dotNet.GetEncoded().Should().Equal(bouncy.GetEncoded());
        }

        [TestMethod]
        public void ECDsaCert()
        {
            var bouncy = BouncyCastleCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyECDsaCertificate);
            var dotNet = DotNetCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetECDsaCertificate);
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
            var bouncy = BouncyCastleCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyRsaCertificate);
            var dotNet = DotNetCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetRsaCertificate);
            dotNet.GetSerialNumber().Should().Be(bouncy.GetSerialNumber());
        }

        [TestMethod]
        public void DsaSerialNumber()
        {
            var bouncy = BouncyCastleCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyDsaCertificate);
            var dotNet = DotNetCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetDsaCertificate);
            dotNet.GetSerialNumber().Should().Be(bouncy.GetSerialNumber());
        }

        [TestMethod]
        public void ECDsaSerialNumber()
        {
            var bouncy = BouncyCastleCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.BouncyECDsaCertificate);
            var dotNet = DotNetCryptographyProvider.INSTANCE.CreateCertificate(BouncyAndDotNetCompatibilityTestData.DotNetECDsaCertificate);
            dotNet.GetSerialNumber().Should().Be(bouncy.GetSerialNumber());
        }
    }
}