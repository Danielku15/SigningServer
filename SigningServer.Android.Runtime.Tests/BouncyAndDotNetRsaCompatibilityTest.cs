using FluentAssertions;
using NUnit.Framework;
using Org.BouncyCastle.Security;
using SigningServer.Android.Security;
using SigningServer.Android.Security.BouncyCastle;
using SigningServer.Android.Security.DotNet;
using PublicKey = SigningServer.Android.Security.PublicKey;

namespace SigningServer.Android.Runtime.Tests;


public class BouncyAndDotNetRsaCompatibilityTest
{
    [TestCase("MD5withRSA")]
    [TestCase("SHA1withRSA")]
    [TestCase("SHA256withRSA")]
    [TestCase("SHA512withRSA")]
    public void SignRsaTest(string signatureAlg)
    {
        SignTest(BouncyAndDotNetCompatibilityTestData.BouncyRsaPrivateKey, BouncyAndDotNetCompatibilityTestData.DotNetRsaPrivateKey, signatureAlg);
    }

    [TestCase("MD5withRSA")]
    [TestCase("SHA1withRSA")]
    [TestCase("SHA256withRSA")]
    [TestCase("SHA512withRSA")]
    public void VerifyRsaTest(string signatureAlg)
    {
        VerifyTest(BouncyAndDotNetCompatibilityTestData.BouncyRsaPrivateKey, BouncyAndDotNetCompatibilityTestData.DotNetRsaPublicKey, signatureAlg);
    }

    [TestCase("MD5withRSA")]
    [TestCase("SHA1withRSA")]
    [TestCase("SHA256withRSA")]
    [TestCase("SHA512withRSA")]
    public void VerifyReverseRsaTest(string signatureAlg)
    {
        VerifyReverseTest(BouncyAndDotNetCompatibilityTestData.BouncyRsaPublicKey, BouncyAndDotNetCompatibilityTestData.DotNetRsaPrivateKey, signatureAlg);
    }

    private void SignTest(PrivateKey bouncyKey, PrivateKey dotNetKey, string signatureAlg)
    {
        var random = new SecureRandom();
        var input = new byte[1024];
        random.NextBytes(input, 0, input.Length);

        var bouncy = BouncyCastleCryptographyProvider.Instance.CreateSignature(signatureAlg);
        bouncy.InitSign(bouncyKey);
        bouncy.Update(input);
        var bouncySignature = bouncy.Sign();

        var dotNet = DotNetCryptographyProvider.Instance.CreateSignature(signatureAlg);
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

        var bouncy = BouncyCastleCryptographyProvider.Instance.CreateSignature(signatureAlg);
        bouncy.InitSign(bouncyKey);
        bouncy.Update(input);
        var bouncySignature = bouncy.Sign();

        var dotNet = DotNetCryptographyProvider.Instance.CreateSignature(signatureAlg);
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

        var dotNet = DotNetCryptographyProvider.Instance.CreateSignature(signatureAlg);
        dotNet.InitSign(dotNetKey);
        dotNet.Update(input);
        var dotNetSignature = dotNet.Sign();

        var bouncy = BouncyCastleCryptographyProvider.Instance.CreateSignature(signatureAlg);
        bouncy.InitVerify(bouncyKey);
        bouncy.Update(input);
        var verified = bouncy.Verify(dotNetSignature);

        verified.Should().BeTrue();
    }
}
