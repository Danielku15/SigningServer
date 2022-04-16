// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SigningServer.Android.Com.Android.Apksig
{
    [TestClass]
    public class SourceStampVerifierTest: SigningServer.Android.TestBase
    {
        internal static readonly string RSA_2048_CERT_SHA256_DIGEST = "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8";
        
        internal static readonly string RSA_2048_2_CERT_SHA256_DIGEST = "681b0e56a796350c08647352a4db800cc44b2adc8f4c72fa350bd05d4d50264d";
        
        internal static readonly string RSA_2048_3_CERT_SHA256_DIGEST = "bb77a72efc60e66501ab75953af735874f82cfe52a70d035186a01b3482180f3";
        
        internal static readonly string EC_P256_CERT_SHA256_DIGEST = "6a8b96e278e58f62cfe3584022cec1d0527fcb85a9e5d2e1694eb0405be5b599";
        
        internal static readonly string EC_P256_2_CERT_SHA256_DIGEST = "d78405f761ff6236cc9b570347a570aba0c62a129a3ac30c831c64d09ad95469";
        
        [Test]
        public virtual void VerifySourceStamp_correctSignature()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("valid-stamp.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            verificationResult = VerifySourceStamp("valid-stamp.apk", 18, 18);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            verificationResult = VerifySourceStamp("valid-stamp.apk", 24, 24);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            verificationResult = VerifySourceStamp("valid-stamp.apk", 28, 28);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
        }
        
        [Test]
        public virtual void VerifySourceStamp_rotatedV3Key_signingCertDigestsMatch()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("v1v2v3-rotated-v3-key-valid-stamp.apk", 23, 28);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_2_CERT_SHA256_DIGEST);
            verificationResult = VerifySourceStamp("v1v2v3-rotated-v3-key-valid-stamp.apk", 18, 18);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST, null, null);
            verificationResult = VerifySourceStamp("v1v2v3-rotated-v3-key-valid-stamp.apk", 24, 24);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, null, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST, null);
            verificationResult = VerifySourceStamp("v1v2v3-rotated-v3-key-valid-stamp.apk", 28, 28);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, null, null, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_2_CERT_SHA256_DIGEST);
        }
        
        [Test]
        public virtual void VerifySourceStamp_signatureMissing()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-without-block.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationFailure(verificationResult, Com.Android.Apksig.ApkVerificationIssue.SOURCE_STAMP_SIG_MISSING);
        }
        
        [Test]
        public virtual void VerifySourceStamp_certificateMismatch()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-certificate-mismatch.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationFailure(verificationResult, Com.Android.Apksig.ApkVerificationIssue.SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK);
        }
        
        [Test]
        public virtual void VerifySourceStamp_v1OnlySignatureValidStamp()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("v1-only-with-stamp.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST, null, null);
            verificationResult = VerifySourceStamp("v1-only-with-stamp.apk", 28, 28);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST, null, null);
            verificationResult = VerifySourceStamp("v1-only-with-stamp.apk", 24, 24);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST, null, null);
        }
        
        [Test]
        public virtual void VerifySourceStamp_v2OnlySignatureValidStamp()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("v2-only-with-stamp.apk", 24, 24);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, null, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST, null);
            verificationResult = VerifySourceStamp("v2-only-with-stamp.apk", 28, 28);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, null, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST, null);
        }
        
        [Test]
        public virtual void VerifySourceStamp_v3OnlySignatureValidStamp()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("v3-only-with-stamp.apk", 28, 28);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, null, null, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST);
        }
        
        [Test]
        public virtual void VerifySourceStamp_apkHashMismatch_v1SignatureScheme()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-apk-hash-mismatch-v1.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationFailure(verificationResult, Com.Android.Apksig.ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY);
        }
        
        [Test]
        public virtual void VerifySourceStamp_apkHashMismatch_v2SignatureScheme()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-apk-hash-mismatch-v2.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationFailure(verificationResult, Com.Android.Apksig.ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY);
        }
        
        [Test]
        public virtual void VerifySourceStamp_apkHashMismatch_v3SignatureScheme()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-apk-hash-mismatch-v3.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationFailure(verificationResult, Com.Android.Apksig.ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY);
        }
        
        [Test]
        public virtual void VerifySourceStamp_malformedSignature()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-malformed-signature.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationFailure(verificationResult, Com.Android.Apksig.ApkVerificationIssue.SOURCE_STAMP_MALFORMED_SIGNATURE);
        }
        
        [Test]
        public virtual void VerifySourceStamp_expectedDigestMatchesActual()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("v3-only-with-stamp.apk", SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.RSA_2048_CERT_SHA256_DIGEST, 28, 28);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
        }
        
        [Test]
        public virtual void VerifySourceStamp_expectedDigestMismatch()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("v3-only-with-stamp.apk", SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.EC_P256_CERT_SHA256_DIGEST);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationFailure(verificationResult, Com.Android.Apksig.ApkVerificationIssue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH);
        }
        
        [Test]
        public virtual void VerifySourceStamp_noStampCertDigestNorSignatureBlock()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("original.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationFailure(verificationResult, Com.Android.Apksig.ApkVerificationIssue.SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING);
        }
        
        [Test]
        public virtual void VerifySourceStamp_validStampLineage()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-lineage-valid.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificatesInLineage(verificationResult, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.RSA_2048_CERT_SHA256_DIGEST, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.RSA_2048_2_CERT_SHA256_DIGEST);
        }
        
        [Test]
        public virtual void VerifySourceStamp_invalidStampLineage()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-lineage-invalid.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationFailure(verificationResult, Com.Android.Apksig.ApkVerificationIssue.SOURCE_STAMP_POR_CERT_MISMATCH);
        }
        
        [Test]
        public virtual void VerifySourceStamp_multipleSignersInLineage()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-lineage-with-3-signers.apk", 18, 28);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificatesInLineage(verificationResult, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.RSA_2048_CERT_SHA256_DIGEST, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.RSA_2048_2_CERT_SHA256_DIGEST, SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.RSA_2048_3_CERT_SHA256_DIGEST);
        }
        
        [Test]
        public virtual void VerifySourceStamp_noSignersInLineage_returnsEmptyLineage()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("valid-stamp.apk");
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificatesInLineage(verificationResult);
        }
        
        [Test]
        public virtual void VerifySourceStamp_noApkSignature_succeeds()
        {
            Com.Android.Apksig.SourceStampVerifier.Result verificationResult = VerifySourceStamp("stamp-without-apk-signature.apk", 18, 28);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertVerified(verificationResult);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSigningCertificates(verificationResult, null, null, null);
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationWarning(verificationResult, Com.Android.Apksig.ApkVerificationIssue.JAR_SIG_NO_SIGNATURES);
        }
        
        internal Com.Android.Apksig.SourceStampVerifier.Result VerifySourceStamp(string apkFilenameInResources)
        {
            return VerifySourceStamp(apkFilenameInResources, null, null, null);
        }
        
        internal Com.Android.Apksig.SourceStampVerifier.Result VerifySourceStamp(string apkFilenameInResources, string expectedCertDigest)
        {
            return VerifySourceStamp(apkFilenameInResources, expectedCertDigest, null, null);
        }
        
        internal Com.Android.Apksig.SourceStampVerifier.Result VerifySourceStamp(string apkFilenameInResources, int? minSdkVersionOverride, int? maxSdkVersionOverride)
        {
            return VerifySourceStamp(apkFilenameInResources, null, minSdkVersionOverride, maxSdkVersionOverride);
        }
        
        internal Com.Android.Apksig.SourceStampVerifier.Result VerifySourceStamp(string apkFilenameInResources, string expectedCertDigest, int? minSdkVersionOverride, int? maxSdkVersionOverride)
        {
            byte[] apkBytes = SigningServer.Android.Com.Android.Apksig.Internal.Util.Resources.ToByteArray(GetType(), apkFilenameInResources);
            Com.Android.Apksig.SourceStampVerifier.Builder builder = new Com.Android.Apksig.SourceStampVerifier.Builder(Com.Android.Apksig.Util.DataSources.AsDataSource(SigningServer.Android.IO.ByteBuffer.Wrap(apkBytes)));
            if (minSdkVersionOverride != null)
            {
                builder.SetMinCheckedPlatformVersion(minSdkVersionOverride.Value);
            }
            if (maxSdkVersionOverride != null)
            {
                builder.SetMaxCheckedPlatformVersion(maxSdkVersionOverride.Value);
            }
            return builder.Build().VerifySourceStamp(expectedCertDigest);
        }
        
        internal static void AssertVerified(Com.Android.Apksig.SourceStampVerifier.Result result)
        {
            if (result.IsVerified())
            {
                return;
            }
            SigningServer.Android.Core.StringBuilder msg = new SigningServer.Android.Core.StringBuilder();
            foreach (Com.Android.Apksig.ApkVerificationIssue error in result.GetAllErrors())
            {
                if (msg.Length() > 0)
                {
                    msg.Append('\n');
                }
                msg.Append(error.ToString());
            }
            Fail("APK failed source stamp verification: " + msg.ToString());
        }
        
        internal static void AssertSourceStampVerificationFailure(Com.Android.Apksig.SourceStampVerifier.Result result, int expectedIssueId)
        {
            if (result.IsVerified())
            {
                Fail("APK source stamp verification succeeded instead of failing with " + expectedIssueId);
                return;
            }
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationIssue(result.GetAllErrors(), expectedIssueId);
        }
        
        internal static void AssertSourceStampVerificationWarning(Com.Android.Apksig.SourceStampVerifier.Result result, int expectedIssueId)
        {
            SigningServer.Android.Com.Android.Apksig.SourceStampVerifierTest.AssertSourceStampVerificationIssue(result.GetAllWarnings(), expectedIssueId);
        }
        
        internal static void AssertSourceStampVerificationIssue(SigningServer.Android.Collections.List<Com.Android.Apksig.ApkVerificationIssue> issues, int expectedIssueId)
        {
            SigningServer.Android.Core.StringBuilder msg = new SigningServer.Android.Core.StringBuilder();
            foreach (Com.Android.Apksig.ApkVerificationIssue issue in issues)
            {
                if (issue.GetIssueId() == expectedIssueId)
                {
                    return;
                }
                if (msg.Length() > 0)
                {
                    msg.Append('\n');
                }
                msg.Append(issue.ToString());
            }
            Fail("APK source stamp verification did not report the expected issue. " + "Expected error ID: " + expectedIssueId + ", actual: " + (msg.Length() > 0 ? msg.ToString() : "No reported issues"));
        }
        
        /// <summary>
        /// Asserts that the provided {@code expectedCertDigests} match their respective signing
        /// certificate digest in the specified {@code result}.
        /// 
        /// &lt;p&gt;{@code expectedCertDigests} should be provided in order of the signature schemes with V1
        /// being the first element, V2 the second, etc. If a signer is not expected to be present for
        /// a signature scheme version a {@code null} value should be provided; for instance if only a V3
        /// signing certificate is expected the following should be provided: {@code null, null,
        /// v3ExpectedCertDigest}.
        /// 
        /// &lt;p&gt;Note, this method only supports a single signer per signature scheme; if an expected
        /// certificate digest is provided for a signature scheme and multiple signers are found an
        /// assertion exception will be thrown.
        /// </summary>
        internal static void AssertSigningCertificates(Com.Android.Apksig.SourceStampVerifier.Result result, params string[] expectedCertDigests)
        {
            for (int i = 0;i < expectedCertDigests.Length;i++)
            {
                SigningServer.Android.Collections.List<Com.Android.Apksig.SourceStampVerifier.Result.SignerInfo> signers = null;
                switch (i)
                {
                    case 0:
                        signers = result.GetV1SchemeSigners();
                        break;
                    case 1:
                        signers = result.GetV2SchemeSigners();
                        break;
                    case 2:
                        signers = result.GetV3SchemeSigners();
                        break;
                    default:
                        Fail("This method only supports verification of the signing certificates up " + "through the V3 Signature Scheme");
                        break;
                }
                if (expectedCertDigests[i] == null)
                {
                    AssertEquals("Did not expect any V" + (i + 1) + " signers, found " + signers.Size(), 0, signers.Size());
                    continue;
                }
                if (signers.Size() != 1)
                {
                    Fail("Expected one V" + (i + 1) + " signer with certificate digest " + expectedCertDigests[i] + ", found " + signers.Size() + " V" + (i + 1) + " signers");
                }
                SigningServer.Android.Security.Cert.X509Certificate signingCertificate = signers.Get(0).GetSigningCertificate();
                AssertNotNull(signingCertificate);
                AssertEquals(expectedCertDigests[i], Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtilsLite.ToHex(Com.Android.Apksig.Apk.ApkUtilsLite.ComputeSha256DigestBytes(signingCertificate.GetEncoded())));
            }
        }
        
        /// <summary>
        /// Asserts that the provided {@code expectedCertDigests} match their respective certificate in
        /// the source stamp's lineage with the oldest signer at element 0.
        /// 
        /// &lt;p&gt;If no values are provided for the expectedCertDigests, the source stamp's lineage will
        /// be checked for an empty {@code List} indicating the source stamp has not been rotated.
        /// </summary>
        internal static void AssertSigningCertificatesInLineage(Com.Android.Apksig.SourceStampVerifier.Result result, params string[] expectedCertDigests)
        {
            SigningServer.Android.Collections.List<SigningServer.Android.Security.Cert.X509Certificate> lineageCertificates = result.GetSourceStampInfo().GetCertificatesInLineage();
            AssertEquals("Unexpected number of lineage certificates", expectedCertDigests.Length, lineageCertificates.Size());
            for (int i = 0;i < expectedCertDigests.Length;i++)
            {
                AssertEquals("Stamp lineage mismatch at signer " + i, expectedCertDigests[i], Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtilsLite.ToHex(Com.Android.Apksig.Apk.ApkUtilsLite.ComputeSha256DigestBytes(lineageCertificates.Get(i).GetEncoded())));
            }
        }
        
    }
    
}
