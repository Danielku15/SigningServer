/*
 * Copyright (C) 2016 The Android Open Source Project
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
using System.ComponentModel;
using System.Reflection;

namespace SigningServer.Android.ApkSig
{
    /**
     * APK signature verifier which mimics the behavior of the Android platform.
     *
     * <p>The verifier is designed to closely mimic the behavior of Android platforms. This is to enable
     * the verifier to be used for checking whether an APK's signatures are expected to verify on
     * Android.
     *
     * <p>Use {@link Builder} to obtain instances of this verifier.
     *
     * @see <a href="https://source.android.com/security/apksigning/index.html">Application Signing</a>
     */
    public class ApkVerifier
    {
        // TODO:

        /**
         * {@link Issue} with associated parameters. {@link #toString()} produces a readable formatted
         * form.
         */
        public class IssueWithParams : ApkVerificationIssue
        {
            private readonly Issue mIssue;
            private readonly Object[] mParams;

            /**
          * Constructs a new {@code IssueWithParams} of the specified type and with provided
          * parameters.
          */
            public IssueWithParams(Issue issue, Object[] parameters) : base(issue.getFormat(), parameters)
            {
                mIssue = issue;
                mParams = parameters;
            }

            /**
             * Returns the type of this issue.
             */
            public Issue getIssue()
            {
                return mIssue;
            }

            /**
             * Returns the parameters of this issue.
             */
            public Object[] getParams()
            {
                return (object[])mParams.Clone();
            }

            /**
             * Returns a readable form of this issue.
             */
            public String toString()
            {
                return String.Format(mIssue.getFormat(), mParams);
            }
        }

        /**
         * Error or warning encountered while verifying an APK's signatures.
         */
        public enum Issue
        {
            /**
             * APK is not JAR-signed.
             */
            [Description("No JAR signatures")] JAR_SIG_NO_SIGNATURES,

            /**
             * APK does not contain any entries covered by JAR signatures.
             */
            [Description("No JAR entries covered by JAR signatures")]
            JAR_SIG_NO_SIGNED_ZIP_ENTRIES,

            /**
             * APK contains multiple entries with the same name.
             *
             * <ul>
             * <li>Parameter 1: name ({@code String})</li>
             * </ul>
             */
            [Description("Duplicate entry: {0}")] JAR_SIG_DUPLICATE_ZIP_ENTRY,

            /**
             * JAR manifest contains a section with a duplicate name.
             *
             * <ul>
             * <li>Parameter 1: section name ({@code String})</li>
             * </ul>
             */
            [Description("Duplicate section in META-INF/MANIFEST.MF: {0}")]
            JAR_SIG_DUPLICATE_MANIFEST_SECTION,

            /**
             * JAR manifest contains a section without a name.
             *
             * <ul>
             * <li>Parameter 1: section index (1-based) ({@code Integer})</li>
             * </ul>
             */
            [Description("Malformed META-INF/MANIFEST.MF: invidual section #{0} does not have a name")]
            JAR_SIG_UNNNAMED_MANIFEST_SECTION,

            /**
             * JAR signature file contains a section without a name.
             *
             * <ul>
             * <li>Parameter 1: signature file name ({@code String})</li>
             * <li>Parameter 2: section index (1-based) ({@code Integer})</li>
             * </ul>
             */
            [Description("Malformed {0}: invidual section #{1} does not have a name")]
            JAR_SIG_UNNNAMED_SIG_FILE_SECTION,

            /** APK is missing the JAR manifest entry (META-INF/MANIFEST.MF). */
            [Description("Missing META-INF/MANIFEST.MF")]
            JAR_SIG_NO_MANIFEST,

            /**
             * JAR manifest references an entry which is not there in the APK.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * </ul>
             */
            [Description("{0} entry referenced by META-INF/MANIFEST.MF not found in the APK")]
            JAR_SIG_MISSING_ZIP_ENTRY_REFERENCED_IN_MANIFEST,

            /**
             * JAR manifest does not list a digest for the specified entry.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * </ul>
             */
            [Description("No digest for {0} in META-INF/MANIFEST.MF")]
            JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_MANIFEST,

            /**
             * JAR signature does not list a digest for the specified entry.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * <li>Parameter 2: signature file name ({@code String})</li>
             * </ul>
             */
            [Description("No digest for {0} in {1}")]
            JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_SIG_FILE,

            /**
             * The specified JAR entry is not covered by JAR signature.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * </ul>
             */
            [Description("{0} entry not signed")] JAR_SIG_ZIP_ENTRY_NOT_SIGNED,

            /**
             * JAR signature uses different set of signers to protect the two specified ZIP entries.
             *
             * <ul>
             * <li>Parameter 1: first entry name ({@code String})</li>
             * <li>Parameter 2: first entry signer names ({@code List<String>})</li>
             * <li>Parameter 3: second entry name ({@code String})</li>
             * <li>Parameter 4: second entry signer names ({@code List<String>})</li>
             * </ul>
             */
            [Description("Entries {0} and {2} are signed with different sets of signers : <{1}> vs <{3}>")]
            JAR_SIG_ZIP_ENTRY_SIGNERS_MISMATCH,

            /**
             * Digest of the specified ZIP entry's data does not match the digest expected by the JAR
             * signature.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * <li>Parameter 2: digest algorithm (e.g., SHA-256) ({@code String})</li>
             * <li>Parameter 3: name of the entry in which the expected digest is specified
             *     ({@code String})</li>
             * <li>Parameter 4: base64-encoded actual digest ({@code String})</li>
             * <li>Parameter 5: base64-encoded expected digest ({@code String})</li>
             * </ul>
             */
            [Description("{1} digest of {0} does not match the digest specified in {2}"
                         + ". Expected: <{4}>, actual: <{3}>")]
            JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY,

            /**
             * Digest of the JAR manifest main section did not verify.
             *
             * <ul>
             * <li>Parameter 1: digest algorithm (e.g., SHA-256) ({@code String})</li>
             * <li>Parameter 2: name of the entry in which the expected digest is specified
             *     ({@code String})</li>
             * <li>Parameter 3: base64-encoded actual digest ({@code String})</li>
             * <li>Parameter 4: base64-encoded expected digest ({@code String})</li>
             * </ul>
             */
            [Description("{0} digest of META-INF/MANIFEST.MF main section does not match the digest"
                         + " specified in {1}. Expected: <{3}>, actual: <{2}>")]
            JAR_SIG_MANIFEST_MAIN_SECTION_DIGEST_DID_NOT_VERIFY,

            /**
             * Digest of the specified JAR manifest section does not match the digest expected by the
             * JAR signature.
             *
             * <ul>
             * <li>Parameter 1: section name ({@code String})</li>
             * <li>Parameter 2: digest algorithm (e.g., SHA-256) ({@code String})</li>
             * <li>Parameter 3: name of the signature file in which the expected digest is specified
             *     ({@code String})</li>
             * <li>Parameter 4: base64-encoded actual digest ({@code String})</li>
             * <li>Parameter 5: base64-encoded expected digest ({@code String})</li>
             * </ul>
             */
            [Description("{1} digest of META-INF/MANIFEST.MF section for {0} does not match the digest"
                         + " specified in {2}. Expected: <{4}>, actual: <{3}>")]
            JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY,

            /**
             * JAR signature file does not contain the whole-file digest of the JAR manifest file. The
             * digest speeds up verification of JAR signature.
             *
             * <ul>
             * <li>Parameter 1: name of the signature file ({@code String})</li>
             * </ul>
             */
            [Description("{0} does not specify digest of META-INF/MANIFEST.MF"
                         + ". This slows down verification.")]
            JAR_SIG_NO_MANIFEST_DIGEST_IN_SIG_FILE,

            /**
             * APK is signed using APK Signature Scheme v2 or newer, but JAR signature file does not
             * contain protections against stripping of these newer scheme signatures.
             *
             * <ul>
             * <li>Parameter 1: name of the signature file ({@code String})</li>
             * </ul>
             */
            [Description("APK is signed using APK Signature Scheme v2 but these signatures may be stripped"
                         + " without being detected because {0} does not contain anti-stripping"
                         + " protections.")]
            JAR_SIG_NO_APK_SIG_STRIP_PROTECTION,

            /**
             * JAR signature of the signer is missing a file/entry.
             *
             * <ul>
             * <li>Parameter 1: name of the encountered file ({@code String})</li>
             * <li>Parameter 2: name of the missing file ({@code String})</li>
             * </ul>
             */
            [Description("Partial JAR signature. Found: {0}, missing: {1}")]
            JAR_SIG_MISSING_FILE,

            /**
             * An exception was encountered while verifying JAR signature contained in a signature block
             * against the signature file.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: name of the signature file ({@code String})</li>
             * <li>Parameter 3: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to verify JAR signature {0} against {1}: {2}")]
            JAR_SIG_VERIFY_EXCEPTION,

            /**
             * JAR signature contains unsupported digest algorithm.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: digest algorithm OID ({@code String})</li>
             * <li>Parameter 3: signature algorithm OID ({@code String})</li>
             * <li>Parameter 4: API Levels on which this combination of algorithms is not supported
             *     ({@code String})</li>
             * <li>Parameter 5: user-friendly variant of digest algorithm ({@code String})</li>
             * <li>Parameter 6: user-friendly variant of signature algorithm ({@code String})</li>
             * </ul>
             */
            [Description("JAR signature {0} uses digest algorithm {4} and signature algorithm %6$s which"
                         + " is not supported on API Level(s) {3} for which this APK is being"
                         + " verified")]
            JAR_SIG_UNSUPPORTED_SIG_ALG,

            /**
             * An exception was encountered while parsing JAR signature contained in a signature block.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to parse JAR signature {0}: {1}")]
            JAR_SIG_PARSE_EXCEPTION,

            /**
             * An exception was encountered while parsing a certificate contained in the JAR signature
             * block.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed certificate in JAR signature {0}: {1}")]
            JAR_SIG_MALFORMED_CERTIFICATE,

            /**
             * JAR signature contained in a signature block file did not verify against the signature
             * file.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * <li>Parameter 2: name of the signature file ({@code String})</li>
             * </ul>
             */
            [Description("JAR signature {0} did not verify against {1}")]
            JAR_SIG_DID_NOT_VERIFY,

            /**
             * JAR signature contains no verified signers.
             *
             * <ul>
             * <li>Parameter 1: name of the signature block file ({@code String})</li>
             * </ul>
             */
            [Description("JAR signature {0} contains no signers")]
            JAR_SIG_NO_SIGNERS,

            /**
             * JAR signature file contains a section with a duplicate name.
             *
             * <ul>
             * <li>Parameter 1: signature file name ({@code String})</li>
             * <li>Parameter 1: section name ({@code String})</li>
             * </ul>
             */
            [Description("Duplicate section in {0}: {1}")]
            JAR_SIG_DUPLICATE_SIG_FILE_SECTION,

            /**
             * JAR signature file's main section doesn't contain the mandatory Signature-Version
             * attribute.
             *
             * <ul>
             * <li>Parameter 1: signature file name ({@code String})</li>
             * </ul>
             */
            [Description("Malformed {0}: missing Signature-Version attribute")]
            JAR_SIG_MISSING_VERSION_ATTR_IN_SIG_FILE,

            /**
             * JAR signature file references an unknown APK signature scheme ID.
             *
             * <ul>
             * <li>Parameter 1: name of the signature file ({@code String})</li>
             * <li>Parameter 2: unknown APK signature scheme ID ({@code} Integer)</li>
             * </ul>
             */
            [Description("JAR signature {0} references unknown APK signature scheme ID: {1}")]
            JAR_SIG_UNKNOWN_APK_SIG_SCHEME_ID,

            /**
             * JAR signature file indicates that the APK is supposed to be signed with a supported APK
             * signature scheme (in addition to the JAR signature) but no such signature was found in
             * the APK.
             *
             * <ul>
             * <li>Parameter 1: name of the signature file ({@code String})</li>
             * <li>Parameter 2: APK signature scheme ID ({@code} Integer)</li>
             * <li>Parameter 3: APK signature scheme English name ({@code} String)</li>
             * </ul>
             */
            [Description("JAR signature {0} indicates the APK is signed using {2} but no such signature"
                         + " was found. Signature stripped?")]
            JAR_SIG_MISSING_APK_SIG_REFERENCED,

            /**
             * JAR entry is not covered by signature and thus unauthorized modifications to its contents
             * will not be detected.
             *
             * <ul>
             * <li>Parameter 1: entry name ({@code String})</li>
             * </ul>
             */
            [Description("{0} not protected by signature. Unauthorized modifications to this JAR entry"
                         + " will not be detected. Delete or move the entry outside of META-INF/.")]
            JAR_SIG_UNPROTECTED_ZIP_ENTRY,

            /**
             * APK which is both JAR-signed and signed using APK Signature Scheme v2 contains an APK
             * Signature Scheme v2 signature from this signer, but does not contain a JAR signature
             * from this signer.
             */
            [Description("No JAR signature from this signer")]
            JAR_SIG_MISSING,

            /**
             * APK is targeting a sandbox version which requires APK Signature Scheme v2 signature but
             * no such signature was found.
             *
             * <ul>
             * <li>Parameter 1: target sandbox version ({@code Integer})</li>
             * </ul>
             */
            [Description("Missing APK Signature Scheme v2 signature required for target sandbox version"
                         + " {0}")]
            NO_SIG_FOR_TARGET_SANDBOX_VERSION,

            /**
             * APK is targeting an SDK version that requires a minimum signature scheme version, but the
             * APK is not signed with that version or later.
             *
             * <ul>
             *     <li>Parameter 1: target SDK Version (@code Integer})</li>
             *     <li>Parameter 2: minimum signature scheme version ((@code Integer})</li>
             * </ul>
             */
            [Description("Target SDK version {0} requires a minimum of signature scheme v{1}; the APK is"
                         + " not signed with this or a later signature scheme")]
            MIN_SIG_SCHEME_FOR_TARGET_SDK_NOT_MET,

            /**
             * APK which is both JAR-signed and signed using APK Signature Scheme v2 contains a JAR
             * signature from this signer, but does not contain an APK Signature Scheme v2 signature
             * from this signer.
             */
            [Description("No APK Signature Scheme v2 signature from this signer")]
            V2_SIG_MISSING,

            /**
             * Failed to parse the list of signers contained in the APK Signature Scheme v2 signature.
             */
            [Description("Malformed list of signers")]
            V2_SIG_MALFORMED_SIGNERS,

            /**
             * Failed to parse this signer's signer block contained in the APK Signature Scheme v2
             * signature.
             */
            [Description("Malformed signer block")]
            V2_SIG_MALFORMED_SIGNER,

            /**
             * Public key embedded in the APK Signature Scheme v2 signature of this signer could not be
             * parsed.
             *
             * <ul>
             * <li>Parameter 1: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed public key: {0}")]
            V2_SIG_MALFORMED_PUBLIC_KEY,

            /**
             * This APK Signature Scheme v2 signer's certificate could not be parsed.
             *
             * <ul>
             * <li>Parameter 1: index ({@code 0}-based) of the certificate in the signer's list of
             *     certificates ({@code Integer})</li>
             * <li>Parameter 2: sequence number ({@code 1}-based) of the certificate in the signer's
             *     list of certificates ({@code Integer})</li>
             * <li>Parameter 3: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed certificate #{1}: {2}")]
            V2_SIG_MALFORMED_CERTIFICATE,

            /**
             * Failed to parse this signer's signature record contained in the APK Signature Scheme v2
             * signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code Integer})</li>
             * </ul>
             */
            [Description("Malformed APK Signature Scheme v2 signature record #{0}")]
            V2_SIG_MALFORMED_SIGNATURE,

            /**
             * Failed to parse this signer's digest record contained in the APK Signature Scheme v2
             * signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code Integer})</li>
             * </ul>
             */
            [Description("Malformed APK Signature Scheme v2 digest record #{0}")]
            V2_SIG_MALFORMED_DIGEST,

            /**
             * This APK Signature Scheme v2 signer contains a malformed additional attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute number (first attribute is {@code 1}) {@code Integer})</li>
             * </ul>
             */
            [Description("Malformed additional attribute #{0}")]
            V2_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE,

            /**
             * APK Signature Scheme v2 signature references an unknown APK signature scheme ID.
             *
             * <ul>
             * <li>Parameter 1: signer index ({@code Integer})</li>
             * <li>Parameter 2: unknown APK signature scheme ID ({@code} Integer)</li>
             * </ul>
             */
            [Description("APK Signature Scheme v2 signer: {0} references unknown APK signature scheme ID: "
                         + "{1}")]
            V2_SIG_UNKNOWN_APK_SIG_SCHEME_ID,

            /**
             * APK Signature Scheme v2 signature indicates that the APK is supposed to be signed with a
             * supported APK signature scheme (in addition to the v2 signature) but no such signature
             * was found in the APK.
             *
             * <ul>
             * <li>Parameter 1: signer index ({@code Integer})</li>
             * <li>Parameter 2: APK signature scheme English name ({@code} String)</li>
             * </ul>
             */
            [Description("APK Signature Scheme v2 signature {0} indicates the APK is signed using {1} but "
                         + "no such signature was found. Signature stripped?")]
            V2_SIG_MISSING_APK_SIG_REFERENCED,

            /**
             * APK Signature Scheme v2 signature contains no signers.
             */
            [Description("No signers in APK Signature Scheme v2 signature")]
            V2_SIG_NO_SIGNERS,

            /**
             * This APK Signature Scheme v2 signer contains a signature produced using an unknown
             * algorithm.
             *
             * <ul>
             * <li>Parameter 1: algorithm ID ({@code Integer})</li>
             * </ul>
             */
            [Description("Unknown signature algorithm: %1$#x")]
            V2_SIG_UNKNOWN_SIG_ALGORITHM,

            /**
             * This APK Signature Scheme v2 signer contains an unknown additional attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute ID ({@code Integer})</li>
             * </ul>
             */
            [Description("Unknown additional attribute: ID %1$#x")]
            V2_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE,

            /**
             * An exception was encountered while verifying APK Signature Scheme v2 signature of this
             * signer.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to verify {0} signature: {1}")]
            V2_SIG_VERIFY_EXCEPTION,

            /**
             * APK Signature Scheme v2 signature over this signer's signed-data block did not verify.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * </ul>
             */
            [Description("{0} signature over signed-data did not verify")]
            V2_SIG_DID_NOT_VERIFY,

            /**
             * This APK Signature Scheme v2 signer offers no signatures.
             */
            [Description("No signatures")] V2_SIG_NO_SIGNATURES,

            /**
             * This APK Signature Scheme v2 signer offers signatures but none of them are supported.
             */
            [Description("No supported signatures: {0}")]
            V2_SIG_NO_SUPPORTED_SIGNATURES,

            /**
             * This APK Signature Scheme v2 signer offers no certificates.
             */
            [Description("No certificates")] V2_SIG_NO_CERTIFICATES,

            /**
             * This APK Signature Scheme v2 signer's public key listed in the signer's certificate does
             * not match the public key listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: hex-encoded public key from certificate ({@code String})</li>
             * <li>Parameter 2: hex-encoded public key from signatures record ({@code String})</li>
             * </ul>
             */
            [Description("Public key mismatch between certificate and signature record: <{0}> vs <{1}>")]
            V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,

            /**
             * This APK Signature Scheme v2 signer's signature algorithms listed in the signatures
             * record do not match the signature algorithms listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: signature algorithms from signatures record ({@code List<Integer>})</li>
             * <li>Parameter 2: signature algorithms from digests record ({@code List<Integer>})</li>
             * </ul>
             */
            [Description("Signature algorithms mismatch between signatures and digests records"
                         + ": {0} vs {1}")]
            V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS,

            /**
             * The APK's digest does not match the digest contained in the APK Signature Scheme v2
             * signature.
             *
             * <ul>
             * <li>Parameter 1: content digest algorithm ({@link ContentDigestAlgorithm})</li>
             * <li>Parameter 2: hex-encoded expected digest of the APK ({@code String})</li>
             * <li>Parameter 3: hex-encoded actual digest of the APK ({@code String})</li>
             * </ul>
             */
            [Description("APK integrity check failed. {0} digest mismatch."
                         + " Expected: <{1}>, actual: <{2}>")]
            V2_SIG_APK_DIGEST_DID_NOT_VERIFY,

            /**
             * Failed to parse the list of signers contained in the APK Signature Scheme v3 signature.
             */
            [Description("Malformed list of signers")]
            V3_SIG_MALFORMED_SIGNERS,

            /**
             * Failed to parse this signer's signer block contained in the APK Signature Scheme v3
             * signature.
             */
            [Description("Malformed signer block")]
            V3_SIG_MALFORMED_SIGNER,

            /**
             * Public key embedded in the APK Signature Scheme v3 signature of this signer could not be
             * parsed.
             *
             * <ul>
             * <li>Parameter 1: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed public key: {0}")]
            V3_SIG_MALFORMED_PUBLIC_KEY,

            /**
             * This APK Signature Scheme v3 signer's certificate could not be parsed.
             *
             * <ul>
             * <li>Parameter 1: index ({@code 0}-based) of the certificate in the signer's list of
             *     certificates ({@code Integer})</li>
             * <li>Parameter 2: sequence number ({@code 1}-based) of the certificate in the signer's
             *     list of certificates ({@code Integer})</li>
             * <li>Parameter 3: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed certificate #{1}: {2}")]
            V3_SIG_MALFORMED_CERTIFICATE,

            /**
             * Failed to parse this signer's signature record contained in the APK Signature Scheme v3
             * signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code Integer})</li>
             * </ul>
             */
            [Description("Malformed APK Signature Scheme v3 signature record #{0}")]
            V3_SIG_MALFORMED_SIGNATURE,

            /**
             * Failed to parse this signer's digest record contained in the APK Signature Scheme v3
             * signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code Integer})</li>
             * </ul>
             */
            [Description("Malformed APK Signature Scheme v3 digest record #{0}")]
            V3_SIG_MALFORMED_DIGEST,

            /**
             * This APK Signature Scheme v3 signer contains a malformed additional attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute number (first attribute is {@code 1}) {@code Integer})</li>
             * </ul>
             */
            [Description("Malformed additional attribute #{0}")]
            V3_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE,

            /**
             * APK Signature Scheme v3 signature contains no signers.
             */
            [Description("No signers in APK Signature Scheme v3 signature")]
            V3_SIG_NO_SIGNERS,

            /**
             * APK Signature Scheme v3 signature contains multiple signers (only one allowed per
             * platform version).
             */
            [Description("Multiple APK Signature Scheme v3 signatures found for a single "
                         + " platform version.")]
            V3_SIG_MULTIPLE_SIGNERS,

            /**
             * APK Signature Scheme v3 signature found, but multiple v1 and/or multiple v2 signers
             * found, where only one may be used with APK Signature Scheme v3
             */
            [Description("Multiple signatures found for pre-v3 signing with an APK "
                         + " Signature Scheme v3 signer.  Only one allowed.")]
            V3_SIG_MULTIPLE_PAST_SIGNERS,

            /**
             * APK Signature Scheme v3 signature found, but its signer doesn't match the v1/v2 signers,
             * or have them as the root of its signing certificate history
             */
            [Description("v3 signer differs from v1/v2 signer without proper signing certificate lineage.")]
            V3_SIG_PAST_SIGNERS_MISMATCH,

            /**
             * This APK Signature Scheme v3 signer contains a signature produced using an unknown
             * algorithm.
             *
             * <ul>
             * <li>Parameter 1: algorithm ID ({@code Integer})</li>
             * </ul>
             */
            [Description("Unknown signature algorithm: %1$#x")]
            V3_SIG_UNKNOWN_SIG_ALGORITHM,

            /**
             * This APK Signature Scheme v3 signer contains an unknown additional attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute ID ({@code Integer})</li>
             * </ul>
             */
            [Description("Unknown additional attribute: ID %1$#x")]
            V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE,

            /**
             * An exception was encountered while verifying APK Signature Scheme v3 signature of this
             * signer.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to verify {0} signature: {1}")]
            V3_SIG_VERIFY_EXCEPTION,

            /**
             * The APK Signature Scheme v3 signer contained an invalid value for either min or max SDK
             * versions.
             *
             * <ul>
             * <li>Parameter 1: minSdkVersion ({@code Integer})
             * <li>Parameter 2: maxSdkVersion ({@code Integer})
             * </ul>
             */
            [Description("Invalid SDK Version parameter(s) encountered in APK Signature "
                         + "scheme v3 signature: minSdkVersion {0} maxSdkVersion: {1}")]
            V3_SIG_INVALID_SDK_VERSIONS,

            /**
             * APK Signature Scheme v3 signature over this signer's signed-data block did not verify.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * </ul>
             */
            [Description("{0} signature over signed-data did not verify")]
            V3_SIG_DID_NOT_VERIFY,

            /**
             * This APK Signature Scheme v3 signer offers no signatures.
             */
            [Description("No signatures")] V3_SIG_NO_SIGNATURES,

            /**
             * This APK Signature Scheme v3 signer offers signatures but none of them are supported.
             */
            [Description("No supported signatures")]
            V3_SIG_NO_SUPPORTED_SIGNATURES,

            /**
             * This APK Signature Scheme v3 signer offers no certificates.
             */
            [Description("No certificates")] V3_SIG_NO_CERTIFICATES,

            /**
             * This APK Signature Scheme v3 signer's minSdkVersion listed in the signer's signed data
             * does not match the minSdkVersion listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: minSdkVersion in signature record ({@code Integer}) </li>
             * <li>Parameter 2: minSdkVersion in signed data ({@code Integer}) </li>
             * </ul>
             */
            [Description("minSdkVersion mismatch between signed data and signature record:"
                         + " <{0}> vs <{1}>")]
            V3_MIN_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD,

            /**
             * This APK Signature Scheme v3 signer's maxSdkVersion listed in the signer's signed data
             * does not match the maxSdkVersion listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: maxSdkVersion in signature record ({@code Integer}) </li>
             * <li>Parameter 2: maxSdkVersion in signed data ({@code Integer}) </li>
             * </ul>
             */
            [Description("maxSdkVersion mismatch between signed data and signature record:"
                         + " <{0}> vs <{1}>")]
            V3_MAX_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD,

            /**
             * This APK Signature Scheme v3 signer's public key listed in the signer's certificate does
             * not match the public key listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: hex-encoded public key from certificate ({@code String})</li>
             * <li>Parameter 2: hex-encoded public key from signatures record ({@code String})</li>
             * </ul>
             */
            [Description("Public key mismatch between certificate and signature record: <{0}> vs <{1}>")]
            V3_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,

            /**
             * This APK Signature Scheme v3 signer's signature algorithms listed in the signatures
             * record do not match the signature algorithms listed in the signatures record.
             *
             * <ul>
             * <li>Parameter 1: signature algorithms from signatures record ({@code List<Integer>})</li>
             * <li>Parameter 2: signature algorithms from digests record ({@code List<Integer>})</li>
             * </ul>
             */
            [Description("Signature algorithms mismatch between signatures and digests records"
                         + ": {0} vs {1}")]
            V3_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS,

            /**
             * The APK's digest does not match the digest contained in the APK Signature Scheme v3
             * signature.
             *
             * <ul>
             * <li>Parameter 1: content digest algorithm ({@link ContentDigestAlgorithm})</li>
             * <li>Parameter 2: hex-encoded expected digest of the APK ({@code String})</li>
             * <li>Parameter 3: hex-encoded actual digest of the APK ({@code String})</li>
             * </ul>
             */
            [Description("APK integrity check failed. {0} digest mismatch."
                         + " Expected: <{1}>, actual: <{2}>")]
            V3_SIG_APK_DIGEST_DID_NOT_VERIFY,

            /**
             * The signer's SigningCertificateLineage attribute containd a proof-of-rotation record with
             * signature(s) that did not verify.
             */
            [Description("SigningCertificateLineage attribute containd a proof-of-rotation"
                         + " record with signature(s) that did not verify.")]
            V3_SIG_POR_DID_NOT_VERIFY,

            /**
             * Failed to parse the SigningCertificateLineage structure in the APK Signature Scheme v3
             * signature's additional attributes section.
             */
            [Description("Failed to parse the SigningCertificateLineage structure in the "
                         + "APK Signature Scheme v3 signature's additional attributes section.")]
            V3_SIG_MALFORMED_LINEAGE,

            /**
             * The APK's signing certificate does not match the terminal node in the provided
             * proof-of-rotation structure describing the signing certificate history
             */
            [Description("APK signing certificate differs from the associated certificate found in the "
                         + "signer's SigningCertificateLineage.")]
            V3_SIG_POR_CERT_MISMATCH,

            /**
             * The APK Signature Scheme v3 signers encountered do not offer a continuous set of
             * supported platform versions.  Either they overlap, resulting in potentially two
             * acceptable signers for a platform version, or there are holes which would create problems
             * in the event of platform version upgrades.
             */
            [Description("APK Signature Scheme v3 signers supported min/max SDK "
                         + "versions are not continuous.")]
            V3_INCONSISTENT_SDK_VERSIONS,

            /**
             * The APK Signature Scheme v3 signers don't cover all requested SDK versions.
             *
             *  <ul>
             * <li>Parameter 1: minSdkVersion ({@code Integer})
             * <li>Parameter 2: maxSdkVersion ({@code Integer})
             * </ul>
             */
            [Description("APK Signature Scheme v3 signers supported min/max SDK "
                         + "versions do not cover the entire desired range.  Found min:  {0} max {1}")]
            V3_MISSING_SDK_VERSIONS,

            /**
             * The SigningCertificateLineages for different platform versions using APK Signature Scheme
             * v3 do not go together.  Specifically, each should be a subset of another, with the size
             * of each increasing as the platform level increases.
             */
            [Description("SigningCertificateLineages targeting different platform versions"
                         + " using APK Signature Scheme v3 are not all a part of the same overall lineage.")]
            V3_INCONSISTENT_LINEAGES,

            /**
             * APK Signing Block contains an unknown entry.
             *
             * <ul>
             * <li>Parameter 1: entry ID ({@code Integer})</li>
             * </ul>
             */
            [Description("APK Signing Block contains unknown entry: ID %1$#x")]
            APK_SIG_BLOCK_UNKNOWN_ENTRY_ID,

            /**
             * Failed to parse this signer's signature record contained in the APK Signature Scheme
             * V4 signature.
             *
             * <ul>
             * <li>Parameter 1: record number (first record is {@code 1}) ({@code Integer})</li>
             * </ul>
             */
            [Description("V4 signature has malformed signer block")]
            V4_SIG_MALFORMED_SIGNERS,

            /**
             * This APK Signature Scheme V4 signer contains a signature produced using an
             * unknown algorithm.
             *
             * <ul>
             * <li>Parameter 1: algorithm ID ({@code Integer})</li>
             * </ul>
             */
            [Description("V4 signature has unknown signing algorithm: %1$#x")]
            V4_SIG_UNKNOWN_SIG_ALGORITHM,

            /**
             * This APK Signature Scheme V4 signer offers no signatures.
             */
            [Description("V4 signature has no signature found")]
            V4_SIG_NO_SIGNATURES,

            /**
             * This APK Signature Scheme V4 signer offers signatures but none of them are
             * supported.
             */
            [Description("V4 signature has no supported signature")]
            V4_SIG_NO_SUPPORTED_SIGNATURES,

            /**
             * APK Signature Scheme v3 signature over this signer's signed-data block did not verify.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * </ul>
             */
            [Description("{0} signature over signed-data did not verify")]
            V4_SIG_DID_NOT_VERIFY,

            /**
             * An exception was encountered while verifying APK Signature Scheme v3 signature of this
             * signer.
             *
             * <ul>
             * <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})</li>
             * <li>Parameter 2: exception ({@code Throwable})</li>
             * </ul>
             */
            [Description("Failed to verify {0} signature: {1}")]
            V4_SIG_VERIFY_EXCEPTION,

            /**
             * Public key embedded in the APK Signature Scheme v4 signature of this signer could not be
             * parsed.
             *
             * <ul>
             * <li>Parameter 1: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("Malformed public key: {0}")]
            V4_SIG_MALFORMED_PUBLIC_KEY,

            /**
             * This APK Signature Scheme V4 signer's certificate could not be parsed.
             *
             * <ul>
             * <li>Parameter 1: index ({@code 0}-based) of the certificate in the signer's list of
             *     certificates ({@code Integer})</li>
             * <li>Parameter 2: sequence number ({@code 1}-based) of the certificate in the signer's
             *     list of certificates ({@code Integer})</li>
             * <li>Parameter 3: error details ({@code Throwable})</li>
             * </ul>
             */
            [Description("V4 signature has malformed certificate")]
            V4_SIG_MALFORMED_CERTIFICATE,

            /**
             * This APK Signature Scheme V4 signer offers no certificate.
             */
            [Description("V4 signature has no certificate")]
            V4_SIG_NO_CERTIFICATE,

            /**
             * This APK Signature Scheme V4 signer's public key listed in the signer's
             * certificate does not match the public key listed in the signature proto.
             *
             * <ul>
             * <li>Parameter 1: hex-encoded public key from certificate ({@code String})</li>
             * <li>Parameter 2: hex-encoded public key from signature proto ({@code String})</li>
             * </ul>
             */
            [Description("V4 signature has mismatched certificate and signature: <{0}> vs <{1}>")]
            V4_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,

            /**
             * The APK's hash root (aka digest) does not match the hash root contained in the Signature
             * Scheme V4 signature.
             *
             * <ul>
             * <li>Parameter 1: content digest algorithm ({@link ContentDigestAlgorithm})</li>
             * <li>Parameter 2: hex-encoded expected digest of the APK ({@code String})</li>
             * <li>Parameter 3: hex-encoded actual digest of the APK ({@code String})</li>
             * </ul>
             */
            [Description("V4 signature's hash tree root (content digest) did not verity")]
            V4_SIG_APK_ROOT_DID_NOT_VERIFY,

            /**
             * The APK's hash tree does not match the hash tree contained in the Signature
             * Scheme V4 signature.
             *
             * <ul>
             * <li>Parameter 1: content digest algorithm ({@link ContentDigestAlgorithm})</li>
             * <li>Parameter 2: hex-encoded expected hash tree of the APK ({@code String})</li>
             * <li>Parameter 3: hex-encoded actual hash tree of the APK ({@code String})</li>
             * </ul>
             */
            [Description("V4 signature's hash tree did not verity")]
            V4_SIG_APK_TREE_DID_NOT_VERIFY,

            /**
             * Using more than one Signer to sign APK Signature Scheme V4 signature.
             */
            [Description("V4 signature only supports one signer")]
            V4_SIG_MULTIPLE_SIGNERS,

            /**
             * The signer used to sign APK Signature Scheme V2/V3 signature does not match the signer
             * used to sign APK Signature Scheme V4 signature.
             */
            [Description("V4 signature and V2/V3 signature have mismatched certificates")]
            V4_SIG_V2_V3_SIGNERS_MISMATCH,

            [Description("V4 signature and V2/V3 signature have mismatched digests")]
            V4_SIG_V2_V3_DIGESTS_MISMATCH,

            /**
             * The v4 signature format version isn't the same as the tool's current version, something
             * may go wrong.
             */
            [Description("V4 signature format version {0} is different from the tool's current "
                         + "version {1}")]
            V4_SIG_VERSION_NOT_CURRENT,

            /**
             * The APK does not contain the source stamp certificate digest file nor the signature block
             * when verification expected a source stamp to be present.
             */
            [Description("Neither the source stamp certificate digest file nor the signature block are "
                         + "present in the APK")]
            SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING,

            /** APK contains SourceStamp file, but does not contain a SourceStamp signature. */
            [Description("No SourceStamp signature")]
            SOURCE_STAMP_SIG_MISSING,

            /**
             * SourceStamp's certificate could not be parsed.
             *
             * <ul>
             *   <li>Parameter 1: error details ({@code Throwable})
             * </ul>
             */
            [Description("Malformed certificate: {0}")]
            SOURCE_STAMP_MALFORMED_CERTIFICATE,

            /** Failed to parse SourceStamp's signature. */
            [Description("Malformed SourceStamp signature")]
            SOURCE_STAMP_MALFORMED_SIGNATURE,

            /**
             * SourceStamp contains a signature produced using an unknown algorithm.
             *
             * <ul>
             *   <li>Parameter 1: algorithm ID ({@code Integer})
             * </ul>
             */
            [Description("Unknown signature algorithm: %1$#x")]
            SOURCE_STAMP_UNKNOWN_SIG_ALGORITHM,

            /**
             * An exception was encountered while verifying SourceStamp signature.
             *
             * <ul>
             *   <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})
             *   <li>Parameter 2: exception ({@code Throwable})
             * </ul>
             */
            [Description("Failed to verify {0} signature: {1}")]
            SOURCE_STAMP_VERIFY_EXCEPTION,

            /**
             * SourceStamp signature block did not verify.
             *
             * <ul>
             *   <li>Parameter 1: signature algorithm ({@link SignatureAlgorithm})
             * </ul>
             */
            [Description("{0} signature over signed-data did not verify")]
            SOURCE_STAMP_DID_NOT_VERIFY,

            /** SourceStamp offers no signatures. */
            [Description("No signature")] SOURCE_STAMP_NO_SIGNATURE,

            /**
             * SourceStamp offers an unsupported signature.
             * <ul>
             *     <li>Parameter 1: list of {@link SignatureAlgorithm}s  in the source stamp
             *     signing block.
             *     <li>Parameter 2: {@code Exception} caught when attempting to obtain the list of
             *     supported signatures.
             * </ul>
             */
            [Description("Signature(s) {{0}} not supported: {1}")]
            SOURCE_STAMP_NO_SUPPORTED_SIGNATURE,

            /**
             * SourceStamp's certificate listed in the APK signing block does not match the certificate
             * listed in the SourceStamp file in the APK.
             *
             * <ul>
             *   <li>Parameter 1: SHA-256 hash of certificate from SourceStamp block in APK signing
             *       block ({@code String})
             *   <li>Parameter 2: SHA-256 hash of certificate from SourceStamp file in APK ({@code
             *       String})
             * </ul>
             */
            [Description("Certificate mismatch between SourceStamp block in APK signing block and"
                         + " SourceStamp file in APK: <{0}> vs <{1}>")]
            SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK,

            /**
             * The APK contains a source stamp signature block without the expected certificate digest
             * in the APK contents.
             */
            [Description("A source stamp signature block was found without a corresponding certificate "
                         + "digest in the APK")]
            SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST,

            /**
             * When verifying just the source stamp, the certificate digest in the APK does not match
             * the expected digest.
             * <ul>
             *     <li>Parameter 1: SHA-256 digest of the source stamp certificate in the APK.
             *     <li>Parameter 2: SHA-256 digest of the expected source stamp certificate.
             * </ul>
             */
            [Description("The source stamp certificate digest in the APK, {0}, does not match the "
                         + "expected digest, {1}")]
            SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH,

            /**
             * Source stamp block contains a malformed attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute number (first attribute is {@code 1}) {@code Integer})</li>
             * </ul>
             */
            [Description("Malformed stamp attribute #{0}")]
            SOURCE_STAMP_MALFORMED_ATTRIBUTE,

            /**
             * Source stamp block contains an unknown attribute.
             *
             * <ul>
             * <li>Parameter 1: attribute ID ({@code Integer})</li>
             * </ul>
             */
            [Description("Unknown stamp attribute: ID %1$#x")]
            SOURCE_STAMP_UNKNOWN_ATTRIBUTE,

            /**
             * Failed to parse the SigningCertificateLineage structure in the source stamp
             * attributes section.
             */
            [Description("Failed to parse the SigningCertificateLineage "
                         + "structure in the source stamp attributes section.")]
            SOURCE_STAMP_MALFORMED_LINEAGE,

            /**
             * The source stamp certificate does not match the terminal node in the provided
             * proof-of-rotation structure describing the stamp certificate history.
             */
            [Description("APK signing certificate differs from the associated certificate found in the "
                         + "signer's SigningCertificateLineage.")]
            SOURCE_STAMP_POR_CERT_MISMATCH,

            /**
             * The source stamp SigningCertificateLineage attribute contains a proof-of-rotation record
             * with signature(s) that did not verify.
             */
            [Description("Source stamp SigningCertificateLineage attribute "
                         + "contains a proof-of-rotation record with signature(s) that did not verify.")]
            SOURCE_STAMP_POR_DID_NOT_VERIFY,

            /**
             * The APK could not be properly parsed due to a ZIP or APK format exception.
             * <ul>
             *     <li>Parameter 1: The {@code Exception} caught when attempting to parse the APK.
             * </ul>
             */
            [Description("Malformed APK; the following exception was caught when attempting to parse the "
                         + "APK: {0}")]
            MALFORMED_APK,

            /**
             * An unexpected exception was caught when attempting to verify the signature(s) within the
             * APK.
             * <ul>
             *     <li>Parameter 1: The {@code Exception} caught during verification.
             * </ul>
             */
            [Description("An unexpected exception was caught when verifying the signature: {0}")]
            UNEXPECTED_EXCEPTION
        }
    }

    public static class ApkVerifierIssueExtensions
    {
        /**
         * Returns the format string suitable for combining the parameters of this issue into a
         * readable string. See {@link java.util.Formatter} for format.
         */
        public static string getFormat(this ApkVerifier.Issue issue)
        {
            return typeof(ApkVerifier.Issue).GetField(issue.ToString())?.GetCustomAttribute<DescriptionAttribute>()
                ?.Description;
        }
    }
}