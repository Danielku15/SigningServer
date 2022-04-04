/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions.Equivalency;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.Test.ApkSig.Internal.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig
{
    [TestClass]
    public class ApkVerifierTest
    {
        private static readonly String[] DSA_KEY_NAMES = { "1024", "2048", "3072" };
        private static readonly String[] DSA_KEY_NAMES_1024_AND_SMALLER = { "1024" };
        private static readonly String[] DSA_KEY_NAMES_2048_AND_LARGER = { "2048", "3072" };
        private static readonly String[] EC_KEY_NAMES = { "p256", "p384", "p521" };
        private static readonly String[] RSA_KEY_NAMES = { "1024", "2048", "3072", "4096", "8192", "16384" };

        private static readonly String[] RSA_KEY_NAMES_2048_AND_LARGER =
        {
            "2048", "3072", "4096", "8192", "16384"
        };

        private static readonly String RSA_2048_CERT_SHA256_DIGEST =
            "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8";

        private static readonly String EC_P256_CERT_SHA256_DIGEST =
            "6a8b96e278e58f62cfe3584022cec1d0527fcb85a9e5d2e1694eb0405be5b599";

        [TestMethod]
        public void testOriginalAccepted()
        {
            // APK signed with v1 and v2 schemes. Obtained by building
            // cts/hostsidetests/appsecurity/test-apps/tinyapp.
            // This APK is used as a basis for many of the other tests here. Hence, we check that this
            // APK verifies.
            assertVerified(verify("original.apk"));
        }

        [TestMethod]
        public void testV1OneSignerMD5withRSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES);
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.4-%s.apk", RSA_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA1withRSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES);
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.5-%s.apk", RSA_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA224withRSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES);
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.14-%s.apk", RSA_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA256withRSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES);
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.11-%s.apk", RSA_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA384withRSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES);
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.12-%s.apk", RSA_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA512withRSAVerifies()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES);
            assertVerifiedForEach(
                "v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.13-%s.apk", RSA_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA1withECDSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach("v1-only-with-ecdsa-sha1-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES);
            assertVerifiedForEach("v1-only-with-ecdsa-sha1-1.2.840.10045.4.1-%s.apk", EC_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA224withECDSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach("v1-only-with-ecdsa-sha224-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES);
            assertVerifiedForEach("v1-only-with-ecdsa-sha224-1.2.840.10045.4.3.1-%s.apk", EC_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA256withECDSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach("v1-only-with-ecdsa-sha256-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES);
            assertVerifiedForEach("v1-only-with-ecdsa-sha256-1.2.840.10045.4.3.2-%s.apk", EC_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA384withECDSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach("v1-only-with-ecdsa-sha384-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES);
            assertVerifiedForEach("v1-only-with-ecdsa-sha384-1.2.840.10045.4.3.3-%s.apk", EC_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA512withECDSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach("v1-only-with-ecdsa-sha512-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES);
            assertVerifiedForEach("v1-only-with-ecdsa-sha512-1.2.840.10045.4.3.4-%s.apk", EC_KEY_NAMES);
        }

        [TestMethod]
        public void testV1OneSignerSHA1withDSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            // NOTE: This test is split into two because JCA Providers shipping with OpenJDK refuse to
            // verify DSA signatures with keys too long for the SHA-1 digest.
            assertVerifiedForEach(
                "v1-only-with-dsa-sha1-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES_1024_AND_SMALLER);
            assertVerifiedForEach(
                "v1-only-with-dsa-sha1-1.2.840.10040.4.3-%s.apk", DSA_KEY_NAMES_1024_AND_SMALLER);
        }

        [TestMethod]
        public void testV1OneSignerSHA1withDSAAcceptedWithKeysTooLongForDigest()
        {
            // APK signed with v1 scheme only, one signer

            // OpenJDK's default implementation of Signature.SHA1withDSA refuses to verify signatures
            // created with keys too long for the digest used. Android Package Manager does not reject
            // such signatures. We thus skip this test if Signature.SHA1withDSA exhibits this issue.
            PublicKey publicKey =
                Resources.toCertificate("dsa-2048.x509.pem").getPublicKey();
            Signature s = Signature.getInstance("SHA1withDSA");
            s.initVerify(publicKey);

            assertVerifiedForEach(
                "v1-only-with-dsa-sha1-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES_2048_AND_LARGER);
            assertVerifiedForEach(
                "v1-only-with-dsa-sha1-1.2.840.10040.4.3-%s.apk", DSA_KEY_NAMES_2048_AND_LARGER);
        }

        [TestMethod]
        public void testV1OneSignerSHA224withDSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            // NOTE: This test is split into two because JCA Providers shipping with OpenJDK refuse to
            // verify DSA signatures with keys too long for the SHA-224 digest.
            assertVerifiedForEach(
                "v1-only-with-dsa-sha224-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES_1024_AND_SMALLER);
            assertVerifiedForEach(
                "v1-only-with-dsa-sha224-2.16.840.1.101.3.4.3.1-%s.apk",
                DSA_KEY_NAMES_1024_AND_SMALLER);
        }

        [TestMethod]
        public void testV1OneSignerSHA224withDSAAcceptedWithKeysTooLongForDigest()
        {
            // APK signed with v1 scheme only, one signer

            // OpenJDK's default implementation of Signature.SHA224withDSA refuses to verify signatures
            // created with keys too long for the digest used. Android Package Manager does not reject
            // such signatures. We thus skip this test if Signature.SHA224withDSA exhibits this issue.
            PublicKey publicKey =
                Resources.toCertificate("dsa-2048.x509.pem").getPublicKey();
            Signature s = Signature.getInstance("SHA224withDSA");
            s.initVerify(publicKey);

            assertVerifiedForEach(
                "v1-only-with-dsa-sha224-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES_2048_AND_LARGER);
            assertVerifiedForEach(
                "v1-only-with-dsa-sha224-2.16.840.1.101.3.4.3.1-%s.apk",
                DSA_KEY_NAMES_2048_AND_LARGER);
        }

        [TestMethod]
        public void testV1OneSignerSHA256withDSAAccepted()
        {
            // APK signed with v1 scheme only, one signer
            assertVerifiedForEach("v1-only-with-dsa-sha256-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES);
            assertVerifiedForEach(
                "v1-only-with-dsa-sha256-2.16.840.1.101.3.4.3.2-%s.apk", DSA_KEY_NAMES);
        }

        [TestMethod]
        public void testV2StrippedRejected()
        {
            // APK signed with v1 and v2 schemes, but v2 signature was stripped from the file (by using
            // zipalign).
            // This should fail because the v1 signature indicates that the APK was supposed to be
            // signed with v2 scheme as well, making the platform's anti-stripping protections reject
            // the APK.
            assertVerificationFailure("v2-stripped.apk", ApkVerifier.Issue.JAR_SIG_MISSING_APK_SIG_REFERENCED);

            // Similar to above, but the X-Android-APK-Signed anti-stripping header in v1 signature
            // lists unknown signature schemes in addition to APK Signature Scheme v2. Unknown schemes
            // should be ignored.
            assertVerificationFailure(
                "v2-stripped-with-ignorable-signing-schemes.apk",
                ApkVerifier.Issue.JAR_SIG_MISSING_APK_SIG_REFERENCED);
        }

        [TestMethod]
        public void testV3StrippedRejected()
        {
            // APK signed with v2 and v3 schemes, but v3 signature was stripped from the file by
            // modifying the v3 block ID to be the verity padding block ID. Without the stripping
            // protection this modification ignores the v3 signing scheme block.
            assertVerificationFailure("v3-stripped.apk", ApkVerifier.Issue.V2_SIG_MISSING_APK_SIG_REFERENCED);
        }

        [TestMethod]
        public void testSignaturesIgnoredForMaxSDK()
        {
            // The V2 signature scheme was introduced in N, and V3 was introduced in P. This test
            // verifies a max SDK of pre-P ignores the V3 signature and a max SDK of pre-N ignores both
            // the V2 and V3 signatures.
            assertVerified(
                verifyForMaxSdkVersion(
                    "v1v2v3-with-rsa-2048-lineage-3-signers.apk", AndroidSdkVersion.O));
            assertVerified(
                verifyForMaxSdkVersion(
                    "v1v2v3-with-rsa-2048-lineage-3-signers.apk", AndroidSdkVersion.M));
        }

        [TestMethod]
        public void testV2OneSignerOneSignatureAccepted()
        {
            // APK signed with v2 scheme only, one signer, one signature
            assertVerifiedForEachForMinSdkVersion(
                "v2-only-with-dsa-sha256-%s.apk", DSA_KEY_NAMES, AndroidSdkVersion.N);
            assertVerifiedForEachForMinSdkVersion(
                "v2-only-with-ecdsa-sha256-%s.apk", EC_KEY_NAMES, AndroidSdkVersion.N);
            assertVerifiedForEachForMinSdkVersion(
                "v2-only-with-rsa-pkcs1-sha256-%s.apk", RSA_KEY_NAMES, AndroidSdkVersion.N);
            // RSA-PSS signatures tested in a separate test below

            // DSA with SHA-512 is not supported by Android platform and thus APK Signature Scheme v2
            // does not support that either
            // assertInstallSucceedsForEach("v2-only-with-dsa-sha512-%s.apk", DSA_KEY_NAMES);
            assertVerifiedForEachForMinSdkVersion(
                "v2-only-with-ecdsa-sha512-%s.apk", EC_KEY_NAMES, AndroidSdkVersion.N);
            assertVerifiedForEachForMinSdkVersion(
                "v2-only-with-rsa-pkcs1-sha512-%s.apk", RSA_KEY_NAMES, AndroidSdkVersion.N);
        }

        [TestMethod]
        public void testV3OneSignerOneSignatureAccepted()
        {
            // APK signed with v3 scheme only, one signer, one signature
            assertVerifiedForEachForMinSdkVersion(
                "v3-only-with-dsa-sha256-%s.apk", DSA_KEY_NAMES, AndroidSdkVersion.P);
            assertVerifiedForEachForMinSdkVersion(
                "v3-only-with-ecdsa-sha256-%s.apk", EC_KEY_NAMES, AndroidSdkVersion.P);
            assertVerifiedForEachForMinSdkVersion(
                "v3-only-with-rsa-pkcs1-sha256-%s.apk", RSA_KEY_NAMES, AndroidSdkVersion.P);

            assertVerifiedForEachForMinSdkVersion(
                "v3-only-with-ecdsa-sha512-%s.apk", EC_KEY_NAMES, AndroidSdkVersion.P);
            assertVerifiedForEachForMinSdkVersion(
                "v3-only-with-rsa-pkcs1-sha512-%s.apk", RSA_KEY_NAMES, AndroidSdkVersion.P);
        }

        [TestMethod]
        public void testV2OneSignerOneRsaPssSignatureAccepted()
        {
            // APK signed with v2 scheme only, one signer, one signature
            assertVerifiedForEachForMinSdkVersion(
                "v2-only-with-rsa-pss-sha256-%s.apk", RSA_KEY_NAMES, AndroidSdkVersion.N);
            assertVerifiedForEachForMinSdkVersion(
                "v2-only-with-rsa-pss-sha512-%s.apk",
                RSA_KEY_NAMES_2048_AND_LARGER, // 1024-bit key is too short for PSS with SHA-512
                AndroidSdkVersion.N);
        }

        [TestMethod]
        public void testV2SignatureDoesNotMatchSignedDataRejected()
        {
            // APK signed with v2 scheme only, but the signature over signed-data does not verify

            // Bitflip in certificate field inside signed-data. Based on
            // v2-only-with-dsa-sha256-1024.apk.
            assertVerificationFailure(
                "v2-only-with-dsa-sha256-1024-sig-does-not-verify.apk",
                ApkVerifier.Issue.V2_SIG_DID_NOT_VERIFY);

            // Signature claims to be RSA PKCS#1 v1.5 with SHA-256, but is actually using SHA-512.
            // Based on v2-only-with-rsa-pkcs1-sha256-2048.apk.
            assertVerificationFailure(
                "v2-only-with-rsa-pkcs1-sha256-2048-sig-does-not-verify.apk",
                ApkVerifier.Issue.V2_SIG_VERIFY_EXCEPTION);

            // Bitflip in the ECDSA signature. Based on v2-only-with-ecdsa-sha256-p256.apk.
            assertVerificationFailure(
                "v2-only-with-ecdsa-sha256-p256-sig-does-not-verify.apk",
                ApkVerifier.Issue.V2_SIG_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void testV3SignatureDoesNotMatchSignedDataRejected()
        {
            // APK signed with v3 scheme only, but the signature over signed-data does not verify

            // Bitflip in DSA signature. Based on v3-only-with-dsa-sha256-2048.apk.
            assertVerificationFailure(
                "v3-only-with-dsa-sha256-2048-sig-does-not-verify.apk",
                ApkVerifier.Issue.V3_SIG_DID_NOT_VERIFY);

            // Bitflip in signed data. Based on v3-only-with-rsa-pkcs1-sha256-3072.apk
            assertVerificationFailure(
                "v3-only-with-rsa-pkcs1-sha256-3072-sig-does-not-verify.apk",
                ApkVerifier.Issue.V3_SIG_DID_NOT_VERIFY);

            // Based on v3-only-with-ecdsa-sha512-p521 with the signature ID changed to be ECDSA with
            // SHA-256.
            assertVerificationFailure(
                "v3-only-with-ecdsa-sha512-p521-sig-does-not-verify.apk",
                ApkVerifier.Issue.V3_SIG_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void testV2RsaPssSignatureDoesNotMatchSignedDataRejected()
        {
            // APK signed with v2 scheme only, but the signature over signed-data does not verify.

            // Signature claims to be RSA PSS with SHA-256 and 32 bytes of salt, but is actually using 0
            // bytes of salt. Based on v2-only-with-rsa-pkcs1-sha256-2048.apk. Obtained by modifying APK
            // signer to use the wrong amount of salt.
            assertVerificationFailure(
                "v2-only-with-rsa-pss-sha256-2048-sig-does-not-verify.apk",
                ApkVerifier.Issue.V2_SIG_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void testV2ContentDigestMismatchRejected()
        {
            // APK signed with v2 scheme only, but the digest of contents does not match the digest
            // stored in signed-data
            ApkVerifier.Issue error = ApkVerifier.Issue.V2_SIG_APK_DIGEST_DID_NOT_VERIFY;

            // Based on v2-only-with-rsa-pkcs1-sha512-4096.apk. Obtained by modifying APK signer to
            // flip the leftmost bit in content digest before signing signed-data.
            assertVerificationFailure("v2-only-with-rsa-pkcs1-sha512-4096-digest-mismatch.apk", error);

            // Based on v2-only-with-ecdsa-sha256-p256.apk. Obtained by modifying APK signer to flip the
            // leftmost bit in content digest before signing signed-data.
            assertVerificationFailure("v2-only-with-ecdsa-sha256-p256-digest-mismatch.apk", error);
        }

        [TestMethod]
        public void testV3ContentDigestMismatchRejected()
        {
            // APK signed with v3 scheme only, but the digest of contents does not match the digest
            // stored in signed-data.

            // Based on v3-only-with-rsa-pkcs1-sha512-8192. Obtained by flipping a bit in the local
            // file header of the APK.
            assertVerificationFailure(
                "v3-only-with-rsa-pkcs1-sha512-8192-digest-mismatch.apk",
                ApkVerifier.Issue.V3_SIG_APK_DIGEST_DID_NOT_VERIFY);

            // Based on v3-only-with-dsa-sha256-3072.apk. Obtained by modifying APK signer to flip the
            // leftmost bit in content digest before signing signed-data.
            assertVerificationFailure(
                "v3-only-with-dsa-sha256-3072-digest-mismatch.apk",
                ApkVerifier.Issue.V3_SIG_APK_DIGEST_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void testNoApkSignatureSchemeBlockRejected()
        {
            // APK signed with v2 scheme only, but the rules for verifying APK Signature Scheme v2
            // signatures say that this APK must not be verified using APK Signature Scheme v2.

            // Obtained from v2-only-with-rsa-pkcs1-sha512-4096.apk by flipping a bit in the magic
            // field in the footer of APK Signing Block. This makes the APK Signing Block disappear.
            assertVerificationFailure(
                "v2-only-wrong-apk-sig-block-magic.apk", ApkVerifier.Issue.JAR_SIG_NO_MANIFEST);

            // Obtained by modifying APK signer to insert "GARBAGE" between ZIP Central Directory and
            // End of Central Directory. The APK is otherwise fine and is signed with APK Signature
            // Scheme v2. Based on v2-only-with-rsa-pkcs1-sha256.apk.
            assertVerificationFailure(
                "v2-only-garbage-between-cd-and-eocd.apk", ApkVerifier.Issue.JAR_SIG_NO_MANIFEST);

            // Obtained by modifying the size in APK Signature Block header. Based on
            // v2-only-with-ecdsa-sha512-p521.apk.
            assertVerificationFailure(
                "v2-only-apk-sig-block-size-mismatch.apk", ApkVerifier.Issue.JAR_SIG_NO_MANIFEST);

            // Obtained by modifying the ID under which APK Signature Scheme v2 Block is stored in
            // APK Signing Block and by modifying the APK signer to not insert anti-stripping
            // protections into JAR Signature. The APK should appear as having no APK Signature Scheme
            // v2 Block and should thus successfully verify using JAR Signature Scheme.
            assertVerified(verify("v1-with-apk-sig-block-but-without-apk-sig-scheme-v2-block.apk"));
        }

        [TestMethod]
        public void testNoV3ApkSignatureSchemeBlockRejected()
        {
            // Obtained from v3-only-with-ecdsa-sha512-p384.apk by flipping a bit in the magic field
            // in the footer of the APK Signing Block.
            assertVerificationFailure(
                "v3-only-with-ecdsa-sha512-p384-wrong-apk-sig-block-magic.apk",
                ApkVerifier.Issue.JAR_SIG_NO_MANIFEST);

            // Obtained from v3-only-with-rsa-pkcs1-sha512-4096.apk by modifying the size in the APK
            // Signature Block header and footer.
            assertVerificationFailure(
                "v3-only-with-rsa-pkcs1-sha512-4096-apk-sig-block-size-mismatch.apk",
                ApkVerifier.Issue.JAR_SIG_NO_MANIFEST);
        }

        [TestMethod]
        [ExpectedException(typeof(ApkFormatException))]
        public void testTruncatedZipCentralDirectoryRejected()
        {
            // Obtained by modifying APK signer to truncate the ZIP Central Directory by one byte. The
            // APK is otherwise fine and is signed with APK Signature Scheme v2. Based on
            // v2-only-with-rsa-pkcs1-sha256.apk
            verify("v2-only-truncated-cd.apk");
        }

        [TestMethod]
        public void testV2UnknownPairIgnoredInApkSigningBlock()
        {
            // Obtained by modifying APK signer to emit an unknown ID-value pair into APK Signing Block
            // before the ID-value pair containing the APK Signature Scheme v2 Block. The unknown
            // ID-value should be ignored.
            assertVerified(
                verifyForMinSdkVersion(
                    "v2-only-unknown-pair-in-apk-sig-block.apk", AndroidSdkVersion.N));
        }

        [TestMethod]
        public void testV3UnknownPairIgnoredInApkSigningBlock()
        {
            // Obtained by modifying APK signer to emit an unknown ID value pair into APK Signing Block
            // before the ID value pair containing the APK Signature Scheme v3 Block. The unknown
            // ID value should be ignored.
            assertVerified(
                verifyForMinSdkVersion(
                    "v3-only-unknown-pair-in-apk-sig-block.apk", AndroidSdkVersion.P));
        }

        [TestMethod]
        public void testV2UnknownSignatureAlgorithmsIgnored()
        {
            // APK is signed with a known signature algorithm and with a couple of unknown ones.
            // Obtained by modifying APK signer to use "unknown" signature algorithms in addition to
            // known ones.
            assertVerified(
                verifyForMinSdkVersion(
                    "v2-only-with-ignorable-unsupported-sig-algs.apk", AndroidSdkVersion.N));
        }

        [TestMethod]
        public void testV3UnknownSignatureAlgorithmsIgnored()
        {
            // APK is signed with a known signature algorithm and a couple of unknown ones.
            // Obtained by modifying APK signer to use "unknown" signature algorithms in addition to
            // known ones.
            assertVerified(
                verifyForMinSdkVersion(
                    "v3-only-with-ignorable-unsupported-sig-algs.apk", AndroidSdkVersion.P));
        }

        [TestMethod]
        public void testV3WithOnlyUnknownSignatureAlgorithmsRejected()
        {
            // APK is only signed with an unknown signature algorithm. Obtained by modifying APK
            // signer's ID for a known signature algorithm.
            assertVerificationFailure(
                "v3-only-no-supported-sig-algs.apk", ApkVerifier.Issue.V3_SIG_NO_SUPPORTED_SIGNATURES);
        }

        [TestMethod]
        public void testV2UnknownAdditionalAttributeIgnored()
        {
            // APK's v2 signature contains an unknown additional attribute, but is otherwise fine.
            // Obtained by modifying APK signer to output an additional attribute with ID 0x01020304
            // and value 0x05060708.
            assertVerified(
                verifyForMinSdkVersion("v2-only-unknown-additional-attr.apk", AndroidSdkVersion.N));
        }

        [TestMethod]
        public void testV3UnknownAdditionalAttributeIgnored()
        {
            // APK's v3 signature contains unknown additional attributes before and after the lineage.
            // Obtained by modifying APK signer to output additional attributes with IDs 0x11223344
            // and 0x99aabbcc with values 0x55667788 and 0xddeeff00
            assertVerified(
                verifyForMinSdkVersion("v3-only-unknown-additional-attr.apk", AndroidSdkVersion.P));

            // APK's v2 and v3 signatures contain unknown additional attributes before and after the
            // anti-stripping and lineage attributes.
            assertVerified(
                verifyForMinSdkVersion("v2v3-unknown-additional-attr.apk", AndroidSdkVersion.P));
        }

        [TestMethod]
        public void testV2MismatchBetweenSignaturesAndDigestsBlockRejected()
        {
            // APK is signed with a single signature algorithm, but the digests block claims that it is
            // signed with two different signature algorithms. Obtained by modifying APK Signer to
            // emit an additional digest record with signature algorithm 0x12345678.
            assertVerificationFailure(
                "v2-only-signatures-and-digests-block-mismatch.apk",
                ApkVerifier.Issue.V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS);
        }

        [TestMethod]
        public void testV3MismatchBetweenSignaturesAndDigestsBlockRejected()
        {
            // APK is signed with a single signature algorithm, but the digests block claims that it is
            // signed with two different signature algorithms. Obtained by modifying APK Signer to
            // emit an additional digest record with signature algorithm 0x11223344.
            assertVerificationFailure(
                "v3-only-signatures-and-digests-block-mismatch.apk",
                ApkVerifier.Issue.V3_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS);
        }

        [TestMethod]
        public void testV2MismatchBetweenPublicKeyAndCertificateRejected()
        {
            // APK is signed with v2 only. The public key field does not match the public key in the
            // leaf certificate. Obtained by modifying APK signer to write out a modified leaf
            // certificate where the RSA modulus has a bitflip.
            assertVerificationFailure(
                "v2-only-cert-and-public-key-mismatch.apk",
                ApkVerifier.Issue.V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD);
        }

        [TestMethod]
        public void testV3MismatchBetweenPublicKeyAndCertificateRejected()
        {
            // APK is signed with v3 only. The public key field does not match the public key in the
            // leaf certificate. Obtained by modifying APK signer to write out a modified leaf
            // certificate where the RSA modulus has a bitflip.
            assertVerificationFailure(
                "v3-only-cert-and-public-key-mismatch.apk",
                ApkVerifier.Issue.V3_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD);
        }

        [TestMethod]
        public void testV2SignerBlockWithNoCertificatesRejected()
        {
            // APK is signed with v2 only. There are no certificates listed in the signer block.
            // Obtained by modifying APK signer to output no certificates.
            assertVerificationFailure("v2-only-no-certs-in-sig.apk", ApkVerifier.Issue.V2_SIG_NO_CERTIFICATES);
        }

        [TestMethod]
        public void testV3SignerBlockWithNoCertificatesRejected()
        {
            // APK is signed with v3 only. There are no certificates listed in the signer block.
            // Obtained by modifying APK signer to output no certificates.
            assertVerificationFailure("v3-only-no-certs-in-sig.apk", ApkVerifier.Issue.V3_SIG_NO_CERTIFICATES);
        }

        [TestMethod]
        public void testTwoSignersAccepted()
        {
            // APK signed by two different signers
            assertVerified(verify("two-signers.apk"));
            assertVerified(verify("v1-only-two-signers.apk"));
            assertVerified(verifyForMinSdkVersion("v2-only-two-signers.apk", AndroidSdkVersion.N));
        }

        [TestMethod]
        public void testV2TwoSignersRejectedWhenOneBroken()
        {
            // Bitflip in the ECDSA signature of second signer. Based on two-signers.apk.
            // This asserts that breakage in any signer leads to rejection of the APK.
            assertVerificationFailure(
                "two-signers-second-signer-v2-broken.apk", ApkVerifier.Issue.V2_SIG_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void testV2TwoSignersRejectedWhenOneWithoutSignatures()
        {
            // APK v2-signed by two different signers. However, there are no signatures for the second
            // signer.
            assertVerificationFailure(
                "v2-only-two-signers-second-signer-no-sig.apk", ApkVerifier.Issue.V2_SIG_NO_SIGNATURES);
        }

        [TestMethod]
        public void testV2TwoSignersRejectedWhenOneWithoutSupportedSignatures()
        {
            // APK v2-signed by two different signers. However, there are no supported signatures for
            // the second signer.
            assertVerificationFailure(
                "v2-only-two-signers-second-signer-no-supported-sig.apk",
                ApkVerifier.Issue.V2_SIG_NO_SUPPORTED_SIGNATURES);
        }

        [TestMethod]
        public void testCorrectCertUsedFromPkcs7SignedDataCertsSet()
        {
            // Obtained by prepending the rsa-1024 certificate to the PKCS#7 SignedData certificates set
            // of v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-2048.apk META-INF/CERT.RSA. The certs
            // (in the order of appearance in the file) are thus: rsa-1024, rsa-2048. The package's
            // signing cert is rsa-2048.
            ApkVerifier.Result result = verify("v1-only-pkcs7-cert-bag-first-cert-not-used.apk");
            assertVerified(result);
            List<X509Certificate> signingCerts = result.getSignerCertificates();
            assertEquals(1, signingCerts.Count);
            assertEquals(
                "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8",
                encodeHex(sha256(signingCerts[0].getEncoded())));
        }

        [TestMethod]
        public void testV1SchemeSignatureCertNotReencoded()
        {
            // Regression test for b/30148997 and b/18228011. When PackageManager does not preserve the
            // original encoded form of signing certificates, bad things happen, such as rejection of
            // completely valid updates to apps. The issue in b/30148997 and b/18228011 was that
            // PackageManager started re-encoding signing certs into DER. This normally produces exactly
            // the original form because X.509 certificates are supposed to be DER-encoded. However, a
            // small fraction of Android apps uses X.509 certificates which are not DER-encoded. For
            // such apps, re-encoding into DER changes the serialized form of the certificate, creating
            // a mismatch with the serialized form stored in the PackageManager database, leading to the
            // rejection of updates for the app.
            //
            // v1-only-with-rsa-1024-cert-not-der.apk cert's signature is not DER-encoded. It is
            // BER-encoded, with length encoded as two bytes instead of just one.
            // v1-only-with-rsa-1024-cert-not-der.apk META-INF/CERT.RSA was obtained from
            // v1-only-with-rsa-1024.apk META-INF/CERT.RSA by manually modifying the ASN.1 structure.
            ApkVerifier.Result result = verify("v1-only-with-rsa-1024-cert-not-der.apk");

            assertVerified(result);
            List<X509Certificate> signingCerts = result.getSignerCertificates();
            assertEquals(1, signingCerts.Count);
            assertEquals(
                "c5d4535a7e1c8111687a8374b2198da6f5ff8d811a7a25aa99ef060669342fa9",
                encodeHex(sha256(signingCerts[0].getEncoded())));
        }

        [TestMethod]
        public void testV1SchemeSignatureCertNotReencoded2()
        {
            // Regression test for b/30148997 and b/18228011. When PackageManager does not preserve the
            // original encoded form of signing certificates, bad things happen, such as rejection of
            // completely valid updates to apps. The issue in b/30148997 and b/18228011 was that
            // PackageManager started re-encoding signing certs into DER. This normally produces exactly
            // the original form because X.509 certificates are supposed to be DER-encoded. However, a
            // small fraction of Android apps uses X.509 certificates which are not DER-encoded. For
            // such apps, re-encoding into DER changes the serialized form of the certificate, creating
            // a mismatch with the serialized form stored in the PackageManager database, leading to the
            // rejection of updates for the app.
            //
            // v1-only-with-rsa-1024-cert-not-der2.apk cert's signature is not DER-encoded. It is
            // BER-encoded, with the BIT STRING value containing an extraneous leading 0x00 byte.
            // v1-only-with-rsa-1024-cert-not-der2.apk META-INF/CERT.RSA was obtained from
            // v1-only-with-rsa-1024.apk META-INF/CERT.RSA by manually modifying the ASN.1 structure.
            ApkVerifier.Result result = verify("v1-only-with-rsa-1024-cert-not-der2.apk");
            assertVerified(result);
            List<X509Certificate> signingCerts = result.getSignerCertificates();
            assertEquals(1, signingCerts.Count);
            assertEquals(
                "da3da398de674541313deed77218ce94798531ea5131bb9b1bb4063ba4548cfb",
                encodeHex(sha256(signingCerts[0].getEncoded())));
        }

        [TestMethod]
        public void testMaxSizedZipEocdCommentAccepted()
        {
            // Obtained by modifying apksigner to produce a max-sized (0xffff bytes long) ZIP End of
            // Central Directory comment, and signing the original.apk using the modified apksigner.
            assertVerified(verify("v1-only-max-sized-eocd-comment.apk"));
            assertVerified(
                verifyForMinSdkVersion("v2-only-max-sized-eocd-comment.apk", AndroidSdkVersion.N));
        }

        [TestMethod]
        public void testEmptyApk()
        {
            // Unsigned empty ZIP archive
            try
            {
                verifyForMinSdkVersion("empty-unsigned.apk", 1);
                fail("ApkFormatException should've been thrown");
            }
            catch (ApkFormatException expected)
            {
            }

            // JAR-signed empty ZIP archive
            try
            {
                verifyForMinSdkVersion("v1-only-empty.apk", 18);
                fail("ApkFormatException should've been thrown");
            }
            catch (ApkFormatException expected)
            {
            }

            // APK Signature Scheme v2 signed empty ZIP archive
            try
            {
                verifyForMinSdkVersion("v2-only-empty.apk", AndroidSdkVersion.N);
                fail("ApkFormatException should've been thrown");
            }
            catch (ApkFormatException expected)
            {
            }

            // APK Signature Scheme v3 signed empty ZIP archive
            try
            {
                verifyForMinSdkVersion("v3-only-empty.apk", AndroidSdkVersion.P);
                fail("ApkFormatException should've been thrown");
            }
            catch (ApkFormatException expected)
            {
            }
        }

        [TestMethod]
        public void testTargetSandboxVersion2AndHigher()
        {
            // This APK (and its variants below) use minSdkVersion 18, meaning it needs to be signed
            // with v1 and v2 schemes

            // This APK is signed with v1 and v2 schemes and thus should verify
            assertVerified(verify("targetSandboxVersion-2.apk"));

            // v1 signature is needed only if minSdkVersion is lower than 24
            assertVerificationFailure(
                verify("v2-only-targetSandboxVersion-2.apk"), ApkVerifier.Issue.JAR_SIG_NO_MANIFEST);
            assertVerified(verifyForMinSdkVersion("v2-only-targetSandboxVersion-2.apk", 24));

            // v2 signature is required
            assertVerificationFailure(
                verify("v1-only-targetSandboxVersion-2.apk"),
                ApkVerifier.Issue.NO_SIG_FOR_TARGET_SANDBOX_VERSION);
            assertVerificationFailure(
                verify("unsigned-targetSandboxVersion-2.apk"),
                ApkVerifier.Issue.NO_SIG_FOR_TARGET_SANDBOX_VERSION);

            // minSdkVersion 28, meaning v1 signature not needed
            assertVerified(verify("v2-only-targetSandboxVersion-3.apk"));
        }

        [TestMethod]
        public void testTargetSdkMinSchemeVersionNotMet()
        {
            // Android 11 / SDK version 30 requires apps targeting this SDK version or higher must be
            // signed with at least the V2 signature scheme. This test verifies if an app is targeting
            // this SDK version and is only signed with a V1 signature then the verifier reports the
            // platform will not accept it.
            assertVerificationFailure(verify("v1-ec-p256-targetSdk-30.apk"),
                ApkVerifier.Issue.MIN_SIG_SCHEME_FOR_TARGET_SDK_NOT_MET);
        }

        [TestMethod]
        public void testTargetSdkMinSchemeVersionMet()
        {
            // This test verifies if an app is signed with the minimum required signature scheme version
            // for the target SDK version then the verifier reports the platform will accept it.
            assertVerified(verify("v2-ec-p256-targetSdk-30.apk"));

            // If an app is only signed with a signature scheme higher than the required version for the
            // target SDK the verifier should also report that the platform will accept it.
            assertVerified(verify("v3-ec-p256-targetSdk-30.apk"));
        }

        [TestMethod]
        public void testTargetSdkMinSchemeVersionNotMetMaxLessThanTarget()
        {
            // If the minimum signature scheme for the target SDK version is not met but the maximum
            // SDK version is less than the target then the verifier should report that the platform
            // will accept it since the specified max SDK version does not know about the minimum
            // signature scheme requirement.
            verifyForMaxSdkVersion("v1-ec-p256-targetSdk-30.apk", 29);
        }

        [TestMethod]
        public void testTargetSdkNoUsesSdkElement()
        {
            // The target SDK minimum signature scheme version check will attempt to obtain the
            // targetSdkVersion attribute value from the uses-sdk element in the AndroidManifest. If
            // the targetSdkVersion is not specified then the verifier should behave the same as the
            // platform; the minSdkVersion should be used when available and when neither the minimum or
            // target SDK are specified a default value of 1 should be used. This test verifies that the
            // verifier does not fail when the uses-sdk element is not specified.
            verify("v1-only-no-uses-sdk.apk");
        }

        [TestMethod]
        public void testV1MultipleDigestAlgsInManifestAndSignatureFile()
        {
            // MANIFEST.MF contains SHA-1 and SHA-256 digests for each entry, .SF contains only SHA-1
            // digests. This file was obtained by:
            //   jarsigner -sigalg SHA256withRSA -digestalg SHA-256 ... <file> ...
            //   jarsigner -sigalg SHA1withRSA -digestalg SHA1 ... <same file> ...
            assertVerified(verify("v1-sha1-sha256-manifest-and-sha1-sf.apk"));

            // MANIFEST.MF and .SF contain SHA-1 and SHA-256 digests for each entry. This file was
            // obtained by modifying apksigner to output multiple digests.
            assertVerified(verify("v1-sha1-sha256-manifest-and-sf.apk"));

            // One of the digests is wrong in either MANIFEST.MF or .SF. These files were obtained by
            // modifying apksigner to output multiple digests and to flip a bit to create a wrong
            // digest.

            // SHA-1 digests in MANIFEST.MF are wrong, but SHA-256 digests are OK.
            // The APK will fail to verify on API Level 17 and lower, but will verify on API Level 18
            // and higher.
            assertVerificationFailure(
                verify("v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-manifest.apk"),
                ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY);
            assertVerificationFailure(
                verifyForMaxSdkVersion(
                    "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-manifest.apk", 17),
                ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY);
            assertVerified(
                verifyForMinSdkVersion(
                    "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-manifest.apk", 18));

            // SHA-1 digests in .SF are wrong, but SHA-256 digests are OK.
            // The APK will fail to verify on API Level 17 and lower, but will verify on API Level 18
            // and higher.
            assertVerificationFailure(
                verify("v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-sf.apk"),
                ApkVerifier.Issue.JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY);
            assertVerificationFailure(
                verifyForMaxSdkVersion(
                    "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-sf.apk", 17),
                ApkVerifier.Issue.JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY);
            assertVerified(
                verifyForMinSdkVersion(
                    "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-sf.apk", 18));

            // SHA-256 digests in MANIFEST.MF are wrong, but SHA-1 digests are OK.
            // The APK will fail to verify on API Level 18 and higher, but will verify on API Level 17
            // and lower.
            assertVerificationFailure(
                verify("v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-manifest.apk"),
                ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY);
            assertVerificationFailure(
                verifyForMinSdkVersion(
                    "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-manifest.apk", 18),
                ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY);
            assertVerified(
                verifyForMaxSdkVersion(
                    "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-manifest.apk", 17));

            // SHA-256 digests in .SF are wrong, but SHA-1 digests are OK.
            // The APK will fail to verify on API Level 18 and higher, but will verify on API Level 17
            // and lower.
            assertVerificationFailure(
                verify("v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-sf.apk"),
                ApkVerifier.Issue.JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY);
            assertVerificationFailure(
                verifyForMinSdkVersion(
                    "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-sf.apk", 18),
                ApkVerifier.Issue.JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY);
            assertVerified(
                verifyForMaxSdkVersion(
                    "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-sf.apk", 17));
        }

        [TestMethod]
        public void testV1WithUnsupportedCharacterInZipEntryName()
        {
            // Android Package Manager does not support ZIP entry names containing CR or LF
            assertVerificationFailure(
                verify("v1-only-with-cr-in-entry-name.apk"),
                ApkVerifier.Issue.JAR_SIG_UNNNAMED_MANIFEST_SECTION);
            assertVerificationFailure(
                verify("v1-only-with-lf-in-entry-name.apk"),
                ApkVerifier.Issue.JAR_SIG_UNNNAMED_MANIFEST_SECTION);
        }

        [TestMethod]
        public void testWeirdZipCompressionMethod()
        {
            // Any ZIP compression method other than STORED is treated as DEFLATED by Android.
            // This APK declares compression method 21 (neither STORED nor DEFLATED) for CERT.RSA entry,
            // but the entry is actually Deflate-compressed.
            assertVerified(verify("weird-compression-method.apk"));
        }

        [TestMethod]
        public void testZipCompressionMethodMismatchBetweenLfhAndCd()
        {
            // Android Package Manager ignores compressionMethod field in Local File Header and always
            // uses the compressionMethod from Central Directory instead.
            // In this APK, compression method of CERT.RSA is declared as STORED in Local File Header
            // and as DEFLATED in Central Directory. The entry is actually Deflate-compressed.
            assertVerified(verify("mismatched-compression-method.apk"));
        }

        [TestMethod]
        public void testV1SignedAttrs()
        {
            String apk = "v1-only-with-signed-attrs.apk";
            assertVerificationFailure(
                verifyForMinSdkVersion(apk, AndroidSdkVersion.JELLY_BEAN_MR2),
                ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION);
            assertVerified(verifyForMinSdkVersion(apk, AndroidSdkVersion.KITKAT));

            apk = "v1-only-with-signed-attrs-signerInfo1-good-signerInfo2-good.apk";
            assertVerificationFailure(
                verifyForMinSdkVersion(apk, AndroidSdkVersion.JELLY_BEAN_MR2),
                ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION);
            assertVerified(verifyForMinSdkVersion(apk, AndroidSdkVersion.KITKAT));
        }

        [TestMethod]
        public void testV1SignedAttrsNotInDerOrder()
        {
            // Android does not re-order SignedAttributes despite it being a SET OF. Pre-N, Android
            // treated them as SEQUENCE OF, meaning no re-ordering is necessary. From N onwards, it
            // treats them as SET OF, but does not re-encode into SET OF during verification if all
            // attributes parsed fine.
            assertVerified(verify("v1-only-with-signed-attrs-wrong-order.apk"));
            assertVerified(
                verify("v1-only-with-signed-attrs-signerInfo1-wrong-order-signerInfo2-good.apk"));
        }

        [TestMethod]
        public void testV1SignedAttrsMissingContentType()
        {
            // SignedAttributes must contain ContentType. Pre-N, Android ignores this requirement.
            // Android N onwards rejects such APKs.
            String apk = "v1-only-with-signed-attrs-missing-content-type.apk";
            assertVerified(verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1));
            assertVerificationFailure(verify(apk), ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION);
            // Assert that this issue fails verification of the entire signature block, rather than
            // skipping the broken SignerInfo. The second signer info SignerInfo verifies fine, but
            // verification does not get there.
            apk = "v1-only-with-signed-attrs-signerInfo1-missing-content-type-signerInfo2-good.apk";
            assertVerified(verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1));
            assertVerificationFailure(verify(apk), ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION);
        }

        [TestMethod]
        public void testV1SignedAttrsWrongContentType()
        {
            // ContentType of SignedAttributes must equal SignedData.encapContentInfo.eContentType.
            // Pre-N, Android ignores this requirement.
            // From N onwards, Android rejects such SignerInfos.
            String apk = "v1-only-with-signed-attrs-wrong-content-type.apk";
            assertVerified(verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1));
            assertVerificationFailure(verify(apk), ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY);
            // First SignerInfo does not verify on Android N and newer, but verification moves on to the
            // second SignerInfo, which verifies.
            apk = "v1-only-with-signed-attrs-signerInfo1-wrong-content-type-signerInfo2-good.apk";
            assertVerified(verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1));
            assertVerified(verifyForMinSdkVersion(apk, AndroidSdkVersion.N));
            // Although the APK's signature verifies on pre-N and N+, we reject such APKs because the
            // APK's verification results in different verified SignerInfos (and thus potentially
            // different signing certs) between pre-N and N+.
            assertVerificationFailure(verify(apk), ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void testV1SignedAttrsMissingDigest()
        {
            // Content digest must be present in SignedAttributes
            String apk = "v1-only-with-signed-attrs-missing-digest.apk";
            assertVerificationFailure(
                verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1),
                ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION);
            assertVerificationFailure(
                verifyForMinSdkVersion(apk, AndroidSdkVersion.N), ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION);
            // Assert that this issue fails verification of the entire signature block, rather than
            // skipping the broken SignerInfo. The second signer info SignerInfo verifies fine, but
            // verification does not get there.
            apk = "v1-only-with-signed-attrs-signerInfo1-missing-digest-signerInfo2-good.apk";
            assertVerificationFailure(
                verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1),
                ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION);
            assertVerificationFailure(
                verifyForMinSdkVersion(apk, AndroidSdkVersion.N), ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION);
        }

        [TestMethod]
        public void testV1SignedAttrsMultipleGoodDigests()
        {
            // Only one content digest must be present in SignedAttributes
            String apk = "v1-only-with-signed-attrs-multiple-good-digests.apk";
            assertVerificationFailure(
                verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1),
                ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION);
            assertVerificationFailure(
                verifyForMinSdkVersion(apk, AndroidSdkVersion.N), ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION);
            // Assert that this issue fails verification of the entire signature block, rather than
            // skipping the broken SignerInfo. The second signer info SignerInfo verifies fine, but
            // verification does not get there.
            apk = "v1-only-with-signed-attrs-signerInfo1-multiple-good-digests-signerInfo2-good.apk";
            assertVerificationFailure(
                verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1),
                ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION);
            assertVerificationFailure(
                verifyForMinSdkVersion(apk, AndroidSdkVersion.N), ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION);
        }

        [TestMethod]
        public void testV1SignedAttrsWrongDigest()
        {
            // Content digest in SignedAttributes does not match the contents
            String apk = "v1-only-with-signed-attrs-wrong-digest.apk";
            assertVerificationFailure(
                verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1), ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY);
            assertVerificationFailure(
                verifyForMinSdkVersion(apk, AndroidSdkVersion.N), ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY);
            // First SignerInfo does not verify, but Android N and newer moves on to the second
            // SignerInfo, which verifies.
            apk = "v1-only-with-signed-attrs-signerInfo1-wrong-digest-signerInfo2-good.apk";
            assertVerificationFailure(
                verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1), ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY);
            assertVerified(verifyForMinSdkVersion(apk, AndroidSdkVersion.N));
        }

        [TestMethod]
        public void testV1SignedAttrsWrongSignature()
        {
            // Signature over SignedAttributes does not verify
            String apk = "v1-only-with-signed-attrs-wrong-signature.apk";
            assertVerificationFailure(
                verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1), ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY);
            assertVerificationFailure(
                verifyForMinSdkVersion(apk, AndroidSdkVersion.N), ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY);
            // First SignerInfo does not verify, but Android N and newer moves on to the second
            // SignerInfo, which verifies.
            apk = "v1-only-with-signed-attrs-signerInfo1-wrong-signature-signerInfo2-good.apk";
            assertVerificationFailure(
                verifyForMaxSdkVersion(apk, AndroidSdkVersion.N - 1), ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY);
            assertVerified(verifyForMinSdkVersion(apk, AndroidSdkVersion.N));
        }

        [TestMethod]
        public void testSourceStampBlock_correctSignature()
        {
            ApkVerifier.Result verificationResult = verify("valid-stamp.apk");
            // Verifies the signature of the APK.
            assertVerified(verificationResult);
            // Verifies the signature of source stamp.
            assertTrue(verificationResult.isSourceStampVerified());
        }

        [TestMethod]
        public void verifySourceStamp_correctSignature()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("valid-stamp.apk");
            // Since the API is only verifying the source stamp the result itself should be marked as
            // verified.
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);

            // The source stamp can also be verified by platform version; confirm the verification works
            // using just the max signature scheme version supported by that platform version.
            verificationResult = verifySourceStamp("valid-stamp.apk", 18, 18);
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);

            verificationResult = verifySourceStamp("valid-stamp.apk", 24, 24);
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);

            verificationResult = verifySourceStamp("valid-stamp.apk", 28, 28);
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);
        }

        [TestMethod]
        public void testSourceStampBlock_signatureMissing()
        {
            ApkVerifier.Result verificationResult = verify("stamp-without-block.apk");
            // A broken stamp should not block a signing scheme verified APK.
            assertVerified(verificationResult);
            assertSourceStampVerificationFailure(verificationResult, ApkVerifier.Issue.SOURCE_STAMP_SIG_MISSING);
        }

        [TestMethod]
        public void verifySourceStamp_signatureMissing()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("stamp-without-block.apk");
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_NOT_VERIFIED);
            assertSourceStampVerificationFailure(verificationResult, ApkVerifier.Issue.SOURCE_STAMP_SIG_MISSING);
        }

        [TestMethod]
        public void testSourceStampBlock_certificateMismatch()
        {
            ApkVerifier.Result verificationResult = verify("stamp-certificate-mismatch.apk");
            // A broken stamp should not block a signing scheme verified APK.
            assertVerified(verificationResult);
            assertSourceStampVerificationFailure(
                verificationResult,
                ApkVerifier.Issue.SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK);
        }

        [TestMethod]
        public void verifySourceStamp_certificateMismatch()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("stamp-certificate-mismatch.apk");
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFICATION_FAILED);
            assertSourceStampVerificationFailure(
                verificationResult,
                ApkVerifier.Issue.SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK);
        }

        [TestMethod]
        public void testSourceStampBlock_v1OnlySignatureValidStamp()
        {
            ApkVerifier.Result verificationResult = verify("v1-only-with-stamp.apk");
            assertVerified(verificationResult);
            assertTrue(verificationResult.isSourceStampVerified());
        }

        [TestMethod]
        public void verifySourceStamp_v1OnlySignatureValidStamp()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("v1-only-with-stamp.apk");
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);

            // Confirm that the source stamp verification succeeds when specifying platform versions
            // that supported later signature scheme versions.
            verificationResult = verifySourceStamp("v1-only-with-stamp.apk", 28, 28);
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);

            verificationResult = verifySourceStamp("v1-only-with-stamp.apk", 24, 24);
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);
        }

        [TestMethod]
        public void testSourceStampBlock_v2OnlySignatureValidStamp()
        {
            ApkVerifier.Result verificationResult = verify("v2-only-with-stamp.apk");
            assertVerified(verificationResult);
            assertTrue(verificationResult.isSourceStampVerified());
        }

        [TestMethod]
        public void verifySourceStamp_v2OnlySignatureValidStamp()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("v2-only-with-stamp.apk");
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);

            // Confirm that the source stamp verification succeeds when specifying a platform version
            // that supports a later signature scheme version.
            verificationResult = verifySourceStamp("v2-only-with-stamp.apk", 28, 28);
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);
        }

        [TestMethod]
        public void testSourceStampBlock_v3OnlySignatureValidStamp()
        {
            ApkVerifier.Result verificationResult = verify("v3-only-with-stamp.apk");
            assertVerified(verificationResult);
            assertTrue(verificationResult.isSourceStampVerified());
        }

        [TestMethod]
        public void verifySourceStamp_v3OnlySignatureValidStamp()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("v3-only-with-stamp.apk");
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);
        }

        [TestMethod]
        public void testSourceStampBlock_apkHashMismatch_v1SignatureScheme()
        {
            ApkVerifier.Result verificationResult = verify("stamp-apk-hash-mismatch-v1.apk");
            // A broken stamp should not block a signing scheme verified APK.
            assertVerified(verificationResult);
            assertSourceStampVerificationFailure(verificationResult, ApkVerifier.Issue.SOURCE_STAMP_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void verifySourceStamp_apkHashMismatch_v1SignatureScheme()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("stamp-apk-hash-mismatch-v1.apk");
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFICATION_FAILED);
            assertSourceStampVerificationFailure(verificationResult, ApkVerifier.Issue.SOURCE_STAMP_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void testSourceStampBlock_apkHashMismatch_v2SignatureScheme()
        {
            ApkVerifier.Result verificationResult = verify("stamp-apk-hash-mismatch-v2.apk");
            // A broken stamp should not block a signing scheme verified APK.
            assertVerified(verificationResult);
            assertSourceStampVerificationFailure(verificationResult, ApkVerifier.Issue.SOURCE_STAMP_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void verifySourceStamp_apkHashMismatch_v2SignatureScheme()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("stamp-apk-hash-mismatch-v2.apk");
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFICATION_FAILED);
            assertSourceStampVerificationFailure(verificationResult, ApkVerifier.Issue.SOURCE_STAMP_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void testSourceStampBlock_apkHashMismatch_v3SignatureScheme()
        {
            ApkVerifier.Result verificationResult = verify("stamp-apk-hash-mismatch-v3.apk");
            // A broken stamp should not block a signing scheme verified APK.
            assertVerified(verificationResult);
            assertSourceStampVerificationFailure(verificationResult, ApkVerifier.Issue.SOURCE_STAMP_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void verifySourceStamp_apkHashMismatch_v3SignatureScheme()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("stamp-apk-hash-mismatch-v3.apk");
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFICATION_FAILED);
            assertSourceStampVerificationFailure(verificationResult, ApkVerifier.Issue.SOURCE_STAMP_DID_NOT_VERIFY);
        }

        [TestMethod]
        public void testSourceStampBlock_malformedSignature()
        {
            ApkVerifier.Result verificationResult = verify("stamp-malformed-signature.apk");
            // A broken stamp should not block a signing scheme verified APK.
            assertVerified(verificationResult);
            assertSourceStampVerificationFailure(
                verificationResult, ApkVerifier.Issue.SOURCE_STAMP_MALFORMED_SIGNATURE);
        }

        [TestMethod]
        public void verifySourceStamp_malformedSignature()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("stamp-malformed-signature.apk");
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFICATION_FAILED);
            assertSourceStampVerificationFailure(
                verificationResult, ApkVerifier.Issue.SOURCE_STAMP_MALFORMED_SIGNATURE);
        }

        [TestMethod]
        public void verifySourceStamp_expectedDigestMatchesActual()
        {
            // The ApkVerifier provides an API to specify the expected certificate digest; this test
            // verifies that the test runs through to completion when the actual digest matches the
            // provided value.
            ApkVerifier.Result verificationResult = verifySourceStamp("v3-only-with-stamp.apk",
                RSA_2048_CERT_SHA256_DIGEST);
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);
        }

        [TestMethod]
        public void verifySourceStamp_expectedDigestMismatch()
        {
            // If the caller requests source stamp verification with an expected cert digest that does
            // not match the actual digest in the APK the verifier should report the mismatch.
            ApkVerifier.Result verificationResult = verifySourceStamp("v3-only-with-stamp.apk",
                EC_P256_CERT_SHA256_DIGEST);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.CERT_DIGEST_MISMATCH);
            assertSourceStampVerificationFailure(verificationResult,
                ApkVerifier.Issue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH);
        }

        [TestMethod]
        public void verifySourceStamp_validStampLineage()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("stamp-lineage-valid.apk");
            assertVerified(verificationResult);
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFIED);
        }

        [TestMethod]
        public void verifySourceStamp_invalidStampLineage()
        {
            ApkVerifier.Result verificationResult = verifySourceStamp("stamp-lineage-invalid.apk");
            assertSourceStampVerificationStatus(verificationResult,
                ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_VERIFICATION_FAILED);
            assertSourceStampVerificationFailure(verificationResult,
                ApkVerifier.Issue.SOURCE_STAMP_POR_CERT_MISMATCH);
        }

        [TestMethod]
        public void apkVerificationIssueAdapter_verifyAllBaseIssuesMapped()
        {
            var fields = typeof(ApkVerificationIssue).GetFields(BindingFlags.Static);
            StringBuilder msg = new StringBuilder();
            foreach (var field in fields)
            {
                // All public static int fields in the ApkVerificationIssue class should be issue IDs;
                // if any are added that are not intended as IDs a filter set should be applied to this
                // test.
                if (field.FieldType == typeof(int))
                {
                    if (!ApkVerifier.ApkVerificationIssueAdapter
                            .sVerificationIssueIdToIssue.ContainsKey((int)field.GetValue(null)))
                    {
                        if (msg.Length > 0)
                        {
                            msg.Append('\n');
                        }

                        msg.Append(
                            "A mapping is required from ApkVerificationIssue." + field.Name
                                                                               + " to an ApkVerifier.Issue in ApkVerificationIssueAdapter");
                    }
                }
            }

            if (msg.Length > 0)
            {
                fail(msg.ToString());
            }
        }

        private ApkVerifier.Result verify(String apkFilenameInResources)
        {
            return verify(apkFilenameInResources, null, null);
        }

        private ApkVerifier.Result verifyForMinSdkVersion(
            String apkFilenameInResources, int minSdkVersion)
        {
            return verify(apkFilenameInResources, minSdkVersion, null);
        }

        private ApkVerifier.Result verifyForMaxSdkVersion(
            String apkFilenameInResources, int maxSdkVersion)
        {
            return verify(apkFilenameInResources, null, maxSdkVersion);
        }

        private ApkVerifier.Result verify(
            String apkFilenameInResources,
            int? minSdkVersionOverride,
            int? maxSdkVersionOverride)
        {
            byte[] apkBytes = Resources.toByteArray(apkFilenameInResources);

            ApkVerifier.Builder builder =
                new ApkVerifier.Builder(DataSources.asDataSource(ByteBuffer.wrap(apkBytes)));
            if (minSdkVersionOverride != null)
            {
                builder.setMinCheckedPlatformVersion(minSdkVersionOverride.Value);
            }

            if (maxSdkVersionOverride != null)
            {
                builder.setMaxCheckedPlatformVersion(maxSdkVersionOverride.Value);
            }

            return builder.build().verify();
        }

        private ApkVerifier.Result verifySourceStamp(String apkFilenameInResources)
        {
            return verifySourceStamp(apkFilenameInResources, null, null, null);
        }

        private ApkVerifier.Result verifySourceStamp(String apkFilenameInResources,
            String expectedCertDigest)
        {
            return verifySourceStamp(apkFilenameInResources, expectedCertDigest, null, null);
        }

        private ApkVerifier.Result verifySourceStamp(String apkFilenameInResources,
            int? minSdkVersionOverride, int? maxSdkVersionOverride)
        {
            return verifySourceStamp(apkFilenameInResources, null, minSdkVersionOverride,
                maxSdkVersionOverride);
        }

        private ApkVerifier.Result verifySourceStamp(String apkFilenameInResources,
            String expectedCertDigest, int? minSdkVersionOverride, int? maxSdkVersionOverride)
        {
            byte[] apkBytes = Resources.toByteArray(apkFilenameInResources);
            ApkVerifier.Builder builder = new ApkVerifier.Builder(
                DataSources.asDataSource(ByteBuffer.wrap(apkBytes)));
            if (minSdkVersionOverride != null)
            {
                builder.setMinCheckedPlatformVersion(minSdkVersionOverride.Value);
            }

            if (maxSdkVersionOverride != null)
            {
                builder.setMaxCheckedPlatformVersion(maxSdkVersionOverride.Value);
            }

            return builder.build().verifySourceStamp(expectedCertDigest);
        }

        public static void assertVerified(ApkVerifier.Result result)
        {
            assertVerified(result, "APK");
        }

        public static void assertVerified(ApkVerifier.Result result, String apkId)
        {
            if (result.isVerified())
            {
                return;
            }

            StringBuilder msg = new StringBuilder();
            foreach (ApkVerifier.IssueWithParams issue in result.getErrors())
            {
                if (msg.Length > 0)
                {
                    msg.Append('\n');
                }

                msg.Append(issue);
            }

            foreach (ApkVerifier.Result.V1SchemeSignerInfo signer in result.getV1SchemeSigners())
            {
                String signerName = signer.getName();
                foreach (ApkVerifier.IssueWithParams issue in
                         signer.getErrors())
                {
                    if (msg.Length > 0)
                    {
                        msg.Append('\n');
                    }

                    msg.Append("JAR signer ")
                        .Append(signerName)
                        .Append(": ")
                        .Append(issue.getIssue())
                        .Append(": ")
                        .Append(issue);
                }
            }

            foreach (ApkVerifier.Result.V2SchemeSignerInfo signer in result.getV2SchemeSigners())
            {
                String signerName = "signer #" + (signer.getIndex() + 1);
                foreach (ApkVerifier.IssueWithParams issue in signer.getErrors())
                {
                    if (msg.Length > 0)
                    {
                        msg.Append('\n');
                    }

                    msg.Append("APK Signature Scheme v2 signer ")
                        .Append(signerName)
                        .Append(": ")
                        .Append(issue.getIssue())
                        .Append(": ")
                        .Append(issue);
                }
            }

            foreach (ApkVerifier.Result.V3SchemeSignerInfo signer in
                     result.getV3SchemeSigners())
            {
                String signerName = "signer #" + (signer.getIndex() + 1);
                foreach (ApkVerifier.IssueWithParams issue in signer.getErrors())
                {
                    if (msg.Length > 0)
                    {
                        msg.Append('\n');
                    }

                    msg.Append("APK Signature Scheme v3 signer ")
                        .Append(signerName)
                        .Append(": ")
                        .Append(issue.getIssue())
                        .Append(": ")
                        .Append(issue);
                }
            }

            fail(apkId + " did not verify: " + msg);
        }

        private void assertVerified(
            String apkFilenameInResources,
            int? minSdkVersionOverride,
            int? maxSdkVersionOverride)
        {
            assertVerified(
                verify(apkFilenameInResources, minSdkVersionOverride, maxSdkVersionOverride),
                apkFilenameInResources);
        }

        public static void assertVerificationFailure(ApkVerifier.Result result, ApkVerifier.Issue expectedIssue)
        {
            if (result.isVerified())
            {
                fail("APK verification succeeded instead of failing with " + expectedIssue);
                return;
            }

            StringBuilder msg = new StringBuilder();
            foreach (ApkVerifier.IssueWithParams issue in result.getErrors())
            {
                if (expectedIssue.Equals(issue.getIssue()))
                {
                    return;
                }

                if (msg.Length > 0)
                {
                    msg.Append('\n');
                }

                msg.Append(issue);
            }

            foreach (ApkVerifier.Result.V1SchemeSignerInfo signer in result.getV1SchemeSigners())
            {
                String signerName = signer.getName();
                foreach (ApkVerifier.IssueWithParams issue in signer.getErrors())
                {
                    if (expectedIssue.Equals(issue.getIssue()))
                    {
                        return;
                    }

                    if (msg.Length > 0)
                    {
                        msg.Append('\n');
                    }

                    msg.Append("JAR signer ")
                        .Append(signerName)
                        .Append(": ")
                        .Append(issue.getIssue())
                        .Append(" ")
                        .Append(issue);
                }
            }

            foreach (ApkVerifier.Result.V2SchemeSignerInfo signer in result.getV2SchemeSigners())
            {
                String signerName = "signer #" + (signer.getIndex() + 1);
                foreach (ApkVerifier.IssueWithParams issue in signer.getErrors())
                {
                    if (expectedIssue.Equals(issue.getIssue()))
                    {
                        return;
                    }

                    if (msg.Length > 0)
                    {
                        msg.Append('\n');
                    }

                    msg.Append("APK Signature Scheme v2 signer ")
                        .Append(signerName)
                        .Append(": ")
                        .Append(issue);
                }
            }

            foreach (ApkVerifier.Result.V3SchemeSignerInfo signer in result.getV3SchemeSigners())
            {
                String signerName = "signer #" + (signer.getIndex() + 1);
                foreach (ApkVerifier.IssueWithParams issue in signer.getErrors())
                {
                    if (expectedIssue.Equals(issue.getIssue()))
                    {
                        return;
                    }

                    if (msg.Length > 0)
                    {
                        msg.Append('\n');
                    }

                    msg.Append("APK Signature Scheme v3 signer ")
                        .Append(signerName)
                        .Append(": ")
                        .Append(issue);
                }
            }

            fail(
                "APK failed verification for the wrong reason"
                + ". Expected: "
                + expectedIssue
                + ", actual: "
                + msg);
        }

        private static void assertSourceStampVerificationFailure(
            ApkVerifier.Result result, ApkVerifier.Issue expectedIssue)
        {
            if (result.isSourceStampVerified())
            {
                fail(
                    "APK source stamp verification succeeded instead of failing with "
                    + expectedIssue);
                return;
            }

            StringBuilder msg = new StringBuilder();
            List<ApkVerifier.IssueWithParams> resultIssueWithParams =
                result.getErrors().Concat(result.getWarnings())
                    .Where(i => i != null)
                    .ToList();
            foreach (ApkVerifier.IssueWithParams issue in resultIssueWithParams)
            {
                if (expectedIssue.Equals(issue.getIssue()))
                {
                    return;
                }

                if (msg.Length > 0)
                {
                    msg.Append('\n');
                }

                msg.Append(issue);
            }

            ApkVerifier.Result.SourceStampInfo signer = result.getSourceStampInfo();
            if (signer != null)
            {
                List<ApkVerifier.IssueWithParams> sourceStampIssueWithParams =
                    signer.getErrors().Concat(signer.getWarnings())
                        .Where(i => i != null)
                        .ToList();
                foreach (ApkVerifier.IssueWithParams issue in sourceStampIssueWithParams)
                {
                    if (expectedIssue.Equals(issue.getIssue()))
                    {
                        return;
                    }

                    if (msg.Length > 0)
                    {
                        msg.Append('\n');
                    }

                    msg.Append("APK SourceStamp signer").Append(": ").Append(issue);
                }
            }

            fail(
                "APK source stamp failed verification for the wrong reason"
                + ". Expected: "
                + expectedIssue
                + ", actual: "
                + msg);
        }

        private static void assertSourceStampVerificationStatus(ApkVerifier.Result result,
            ApkVerifier.Result.SourceStampInfo.SourceStampVerificationStatus verificationStatus)
        {
            assertEquals(verificationStatus,
                result.getSourceStampInfo().getSourceStampVerificationStatus());
        }

        public void assertVerificationFailure(
            String apkFilenameInResources, ApkVerifier.Issue expectedIssue)
        {
            assertVerificationFailure(verify(apkFilenameInResources), expectedIssue);
        }

        private void assertVerifiedForEach(String apkFilenamePatternInResources, String[] args)
        {
            assertVerifiedForEach(apkFilenamePatternInResources, args, null, null);
        }

        private void assertVerifiedForEach(
            String apkFilenamePatternInResources,
            String[] args,
            int? minSdkVersionOverride,
            int? maxSdkVersionOverride)
        {
            foreach (String arg in args)
            {
                String apkFilenameInResources =
                    String.Format(CultureInfo.InvariantCulture, apkFilenamePatternInResources, arg);
                assertVerified(apkFilenameInResources, minSdkVersionOverride, maxSdkVersionOverride);
            }
        }

        private void assertVerifiedForEachForMinSdkVersion(
            String apkFilenameInResources, String[] args, int minSdkVersion)
        {
            assertVerifiedForEach(apkFilenameInResources, args, minSdkVersion, null);
        }

        private static byte[] sha256(byte[] msg)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(msg);
            }
        }
    }
}