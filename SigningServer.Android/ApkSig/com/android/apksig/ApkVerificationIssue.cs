// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig
{
    /// <summary>
    /// This class is intended as a lightweight representation of an APK signature verification issue
    /// where the client does not require the additional textual details provided by a subclass.
    /// </summary>
    public class ApkVerificationIssue
    {
        public static readonly int V2_SIG_MALFORMED_SIGNERS = 1;
        
        public static readonly int V2_SIG_NO_SIGNERS = 2;
        
        public static readonly int V2_SIG_MALFORMED_SIGNER = 3;
        
        public static readonly int V2_SIG_MALFORMED_SIGNATURE = 4;
        
        public static readonly int V2_SIG_NO_SIGNATURES = 5;
        
        public static readonly int V2_SIG_MALFORMED_CERTIFICATE = 6;
        
        public static readonly int V2_SIG_NO_CERTIFICATES = 7;
        
        public static readonly int V2_SIG_MALFORMED_DIGEST = 8;
        
        public static readonly int V3_SIG_MALFORMED_SIGNERS = 9;
        
        public static readonly int V3_SIG_NO_SIGNERS = 10;
        
        public static readonly int V3_SIG_MALFORMED_SIGNER = 11;
        
        public static readonly int V3_SIG_MALFORMED_SIGNATURE = 12;
        
        public static readonly int V3_SIG_NO_SIGNATURES = 13;
        
        public static readonly int V3_SIG_MALFORMED_CERTIFICATE = 14;
        
        public static readonly int V3_SIG_NO_CERTIFICATES = 15;
        
        public static readonly int V3_SIG_MALFORMED_DIGEST = 16;
        
        public static readonly int SOURCE_STAMP_NO_SIGNATURE = 17;
        
        public static readonly int SOURCE_STAMP_MALFORMED_CERTIFICATE = 18;
        
        public static readonly int SOURCE_STAMP_UNKNOWN_SIG_ALGORITHM = 19;
        
        public static readonly int SOURCE_STAMP_MALFORMED_SIGNATURE = 20;
        
        public static readonly int SOURCE_STAMP_DID_NOT_VERIFY = 21;
        
        public static readonly int SOURCE_STAMP_VERIFY_EXCEPTION = 22;
        
        public static readonly int SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH = 23;
        
        public static readonly int SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST = 24;
        
        public static readonly int SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING = 25;
        
        public static readonly int SOURCE_STAMP_NO_SUPPORTED_SIGNATURE = 26;
        
        public static readonly int SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK = 27;
        
        public static readonly int MALFORMED_APK = 28;
        
        public static readonly int UNEXPECTED_EXCEPTION = 29;
        
        public static readonly int SOURCE_STAMP_SIG_MISSING = 30;
        
        public static readonly int SOURCE_STAMP_MALFORMED_ATTRIBUTE = 31;
        
        public static readonly int SOURCE_STAMP_UNKNOWN_ATTRIBUTE = 32;
        
        /// <summary>
        /// Failed to parse the SigningCertificateLineage structure in the source stamp
        /// attributes section.
        /// </summary>
        public static readonly int SOURCE_STAMP_MALFORMED_LINEAGE = 33;
        
        /// <summary>
        /// The source stamp certificate does not match the terminal node in the provided
        /// proof-of-rotation structure describing the stamp certificate history.
        /// </summary>
        public static readonly int SOURCE_STAMP_POR_CERT_MISMATCH = 34;
        
        /// <summary>
        /// The source stamp SigningCertificateLineage attribute contains a proof-of-rotation record
        /// with signature(s) that did not verify.
        /// </summary>
        public static readonly int SOURCE_STAMP_POR_DID_NOT_VERIFY = 35;
        
        /// <summary>
        /// No V1 / jar signing signature blocks were found in the APK.
        /// </summary>
        public static readonly int JAR_SIG_NO_SIGNATURES = 36;
        
        /// <summary>
        /// An exception was encountered when parsing the V1 / jar signer in the signature block.
        /// </summary>
        public static readonly int JAR_SIG_PARSE_EXCEPTION = 37;
        
        internal readonly int mIssueId;
        
        internal readonly string mFormat;
        
        internal readonly object[] mParams;
        
        /// <summary>
        /// Constructs a new {@code ApkVerificationIssue} using the provided {@code format} string and
        /// {@code params}.
        /// </summary>
        public ApkVerificationIssue(string format, params object[] parameters)
        {
            mIssueId = -1;
            mFormat = format;
            mParams = parameters;
        }
        
        /// <summary>
        /// Constructs a new {@code ApkVerificationIssue} using the provided {@code issueId} and {@code
        /// params}.
        /// </summary>
        public ApkVerificationIssue(int issueId, params object[] parameters)
        {
            mIssueId = issueId;
            mFormat = null;
            mParams = parameters;
        }
        
        /// <summary>
        /// Returns the numeric ID for this issue.
        /// </summary>
        public virtual int GetIssueId()
        {
            return mIssueId;
        }
        
        /// <summary>
        /// Returns the optional parameters for this issue.
        /// </summary>
        public virtual object[] GetParams()
        {
            return mParams;
        }
        
        public override string ToString()
        {
            if (mFormat != null)
            {
                return SigningServer.Android.Core.StringExtensions.Format(mFormat, mParams);
            }
            SigningServer.Android.Core.StringBuilder result = new SigningServer.Android.Core.StringBuilder("mIssueId: ").Append(mIssueId);
            foreach (object param in mParams)
            {
                result.Append(", ").Append(param.ToString());
            }
            return result.ToString();
        }
        
    }
    
}
