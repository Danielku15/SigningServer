using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Security;
using SigningServer.Android.Security;
using SigningServer.Android.Security.BouncyCastle;
using SigningServer.Android.Security.DotNet;
using PublicKey = SigningServer.Android.Security.PublicKey;

namespace SigningServer.Android
{
    [TestClass]
    public class BouncyAndDotNetRsaCompatibilityTest
    {
        [DataTestMethod]
        [DataRow("MD5withRSA")]
        [DataRow("SHA1withRSA")]
        [DataRow("SHA256withRSA")]
        [DataRow("SHA512withRSA")]
        public void SignRsaTest(string signatureAlg)
        {
            SignTest(BouncyAndDotNetCompatibilityTestData.BouncyRsaPrivateKey, BouncyAndDotNetCompatibilityTestData.DotNetRsaPrivateKey, signatureAlg);
        }

        [DataTestMethod]
        [DataRow("MD5withRSA")]
        [DataRow("SHA1withRSA")]
        [DataRow("SHA256withRSA")]
        [DataRow("SHA512withRSA")]
        public void VerifyRsaTest(string signatureAlg)
        {
            VerifyTest(BouncyAndDotNetCompatibilityTestData.BouncyRsaPrivateKey, BouncyAndDotNetCompatibilityTestData.DotNetRsaPublicKey, signatureAlg);
        }

        [DataTestMethod]
        [DataRow("MD5withRSA")]
        [DataRow("SHA1withRSA")]
        [DataRow("SHA256withRSA")]
        [DataRow("SHA512withRSA")]
        public void VerifyReverseRsaTest(string signatureAlg)
        {
            VerifyReverseTest(BouncyAndDotNetCompatibilityTestData.BouncyRsaPublicKey, BouncyAndDotNetCompatibilityTestData.DotNetRsaPrivateKey, signatureAlg);
        }

        private void SignTest(PrivateKey bouncyKey, PrivateKey dotNetKey, string signatureAlg)
        {
            var random = new SecureRandom();
            var input = new byte[1024];
            random.NextBytes(input, 0, input.Length);

            var bouncy = BouncyCastleCryptographyProvider.INSTANCE.CreateSignature(signatureAlg);
            bouncy.InitSign(bouncyKey);
            bouncy.Update(input);
            var bouncySignature = bouncy.Sign();

            var dotNet = DotNetCryptographyProvider.INSTANCE.CreateSignature(signatureAlg);
            dotNet.InitSign(dotNetKey);
            dotNet.Update(input);
            var dotNetSignature = dotNet.Sign();

            dotNetSignature.Should().Equal(bouncySignature);
        }

        private void VerifyTest(PrivateKey bouncyKey, PublicKey dotNetKey, string signatureAlg)
        {
            var random = new SecureRandom();
            var input = new byte[1024];
            random.NextBytes(input, 0, input.Length);

            var bouncy = BouncyCastleCryptographyProvider.INSTANCE.CreateSignature(signatureAlg);
            bouncy.InitSign(bouncyKey);
            bouncy.Update(input);
            var bouncySignature = bouncy.Sign();

            var dotNet = DotNetCryptographyProvider.INSTANCE.CreateSignature(signatureAlg);
            dotNet.InitVerify(dotNetKey);
            dotNet.Update(input);
            var verified = dotNet.Verify(bouncySignature);

            verified.Should().BeTrue();
        }

        private void VerifyReverseTest(PublicKey bouncyKey, PrivateKey dotNetKey, string signatureAlg)
        {
            var random = new SecureRandom();
            var input = new byte[1024];
            random.NextBytes(input, 0, input.Length);

            var dotNet = DotNetCryptographyProvider.INSTANCE.CreateSignature(signatureAlg);
            dotNet.InitSign(dotNetKey);
            dotNet.Update(input);
            var dotNetSignature = dotNet.Sign();

            var bouncy = BouncyCastleCryptographyProvider.INSTANCE.CreateSignature(signatureAlg);
            bouncy.InitVerify(bouncyKey);
            bouncy.Update(input);
            var verified = bouncy.Verify(dotNetSignature);

            verified.Should().BeTrue();
        }
    }
}