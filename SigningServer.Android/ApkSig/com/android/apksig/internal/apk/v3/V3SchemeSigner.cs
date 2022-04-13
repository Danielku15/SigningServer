// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3
{
    /// <summary>
    /// APK Signature Scheme v3 signer.
    /// 
    /// &lt;p&gt;APK Signature Scheme v3 builds upon APK Signature Scheme v3, and maintains all of the APK
    /// Signature Scheme v2 goals.
    /// 
    /// @see &lt;a href="https://source.android.com/security/apksigning/v2.html"&gt;APK Signature Scheme v2&lt;/a&gt;
    ///     &lt;p&gt;The main contribution of APK Signature Scheme v3 is the introduction of the {@link
    ///     SigningCertificateLineage}, which enables an APK to change its signing certificate as long as
    ///     it can prove the new siging certificate was signed by the old.
    /// </summary>
    public abstract class V3SchemeSigner
    {
        public static readonly int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID;
        
        public static readonly int PROOF_OF_ROTATION_ATTR_ID = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeConstants.PROOF_OF_ROTATION_ATTR_ID;
        
        /// <summary>
        /// Hidden constructor to prevent instantiation.
        /// </summary>
        internal V3SchemeSigner()
        {
        }
        
        /// <summary>
        /// Gets the APK Signature Scheme v3 signature algorithms to be used for signing an APK using the
        /// provided key.
        /// 
        /// @param minSdkVersion minimum API Level of the platform on which the APK may be installed (see
        ///     AndroidManifest.xml minSdkVersion attribute).
        /// @throws InvalidKeyException if the provided key is not suitable for signing APKs using APK
        ///     Signature Scheme v3
        /// </summary>
        public static SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm> GetSuggestedSignatureAlgorithms(SigningServer.Android.Security.PublicKey signingKey, int minSdkVersion, bool verityEnabled, bool deterministicDsaSigning)
        {
            string keyAlgorithm = signingKey.GetAlgorithm();
            if ("RSA".EqualsIgnoreCase(keyAlgorithm))
            {
                int modulusLengthBits = ((SigningServer.Android.Security.Interfaces.RSAKey)signingKey).GetModulus().BitLength();
                if (modulusLengthBits <= 3072)
                {
                    SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm> algorithms = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm>();
                    algorithms.Add(SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256);
                    if (verityEnabled)
                    {
                        algorithms.Add(SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.VERITY_RSA_PKCS1_V1_5_WITH_SHA256);
                    }
                    return algorithms;
                }
                else 
                {
                    return SigningServer.Android.Util.Collections.SingletonList<SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm>(SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA512);
                }
            }
            else if ("DSA".EqualsIgnoreCase(keyAlgorithm))
            {
                SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm> algorithms = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm>();
                algorithms.Add(deterministicDsaSigning ? SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.DETDSA_WITH_SHA256 : SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.DSA_WITH_SHA256);
                if (verityEnabled)
                {
                    algorithms.Add(SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.VERITY_DSA_WITH_SHA256);
                }
                return algorithms;
            }
            else if ("EC".EqualsIgnoreCase(keyAlgorithm))
            {
                int keySizeBits = ((SigningServer.Android.Security.Interfaces.ECKey)signingKey).GetParams().GetOrder().BitLength();
                if (keySizeBits <= 256)
                {
                    SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm> algorithms = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm>();
                    algorithms.Add(SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.ECDSA_WITH_SHA256);
                    if (verityEnabled)
                    {
                        algorithms.Add(SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.VERITY_ECDSA_WITH_SHA256);
                    }
                    return algorithms;
                }
                else 
                {
                    return SigningServer.Android.Util.Collections.SingletonList<SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm>(SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.ECDSA_WITH_SHA512);
                }
            }
            else 
            {
                throw new SigningServer.Android.Security.InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
            }
        }
        
        public static SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SigningSchemeBlockAndDigests GenerateApkSignatureSchemeV3Block(SigningServer.Android.Com.Android.Apksig.Util.RunnablesExecutor executor, SigningServer.Android.Com.Android.Apksig.Util.DataSource beforeCentralDir, SigningServer.Android.Com.Android.Apksig.Util.DataSource centralDir, SigningServer.Android.Com.Android.Apksig.Util.DataSource eocd, SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig> signerConfigs)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig>, SigningServer.Android.Collections.Map<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, sbyte[]>> digestInfo = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.ComputeContentDigests(executor, beforeCentralDir, centralDir, eocd, signerConfigs);
            return new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SigningSchemeBlockAndDigests(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.GenerateApkSignatureSchemeV3Block(digestInfo.GetFirst(), digestInfo.GetSecond()), digestInfo.GetSecond());
        }
        
        public static sbyte[] GenerateV3SignerAttribute(SigningServer.Android.Com.Android.Apksig.SigningCertificateLineage signingCertificateLineage)
        {
            sbyte[] encodedLineage = signingCertificateLineage.EncodeSigningCertificateLineage();
            int payloadSize = 4 + 4 + encodedLineage.Length;
            SigningServer.Android.IO.ByteBuffer result = SigningServer.Android.IO.ByteBuffer.Allocate(payloadSize);
            result.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            result.PutInt(4 + encodedLineage.Length);
            result.PutInt(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeConstants.PROOF_OF_ROTATION_ATTR_ID);
            result.Put(encodedLineage);
            return result.Array();
        }
        
        internal static SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<sbyte[], int?> GenerateApkSignatureSchemeV3Block(SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig> signerConfigs, SigningServer.Android.Collections.Map<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, sbyte[]> contentDigests)
        {
            SigningServer.Android.Collections.List<sbyte[]> signerBlocks = new SigningServer.Android.Collections.List<sbyte[]>(signerConfigs.Size());
            int signerNumber = 0;
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig signerConfig in signerConfigs)
            {
                signerNumber++;
                sbyte[] signerBlock;
                try
                {
                    signerBlock = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.GenerateSignerBlock(signerConfig, contentDigests);
                }
                catch (SigningServer.Android.Security.InvalidKeyException e)
                {
                    throw new SigningServer.Android.Security.InvalidKeyException("Signer #" + signerNumber + " failed", e);
                }
                catch (SigningServer.Android.Security.SignatureException e)
                {
                    throw new SigningServer.Android.Security.SignatureException("Signer #" + signerNumber + " failed", e);
                }
                signerBlocks.Add(signerBlock);
            }
            return SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<sbyte[], int>(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedElements(new sbyte[]{
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedElements(signerBlocks)}
            ), SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID);
        }
        
        internal static sbyte[] GenerateSignerBlock(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig signerConfig, SigningServer.Android.Collections.Map<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, sbyte[]> contentDigests)
        {
            if (signerConfig.certificates.IsEmpty())
            {
                throw new SigningServer.Android.Security.SignatureException("No certificates configured for signer");
            }
            SigningServer.Android.Security.PublicKey publicKey = signerConfig.certificates.Get(0).GetPublicKey();
            sbyte[] encodedPublicKey = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodePublicKey(publicKey);
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.V3SignatureSchemeBlock.SignedData signedData = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.V3SignatureSchemeBlock.SignedData();
            try
            {
                signedData.certificates = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeCertificates(signerConfig.certificates);
            }
            catch (SigningServer.Android.Security.Cert.CertificateEncodingException e)
            {
                throw new SigningServer.Android.Security.SignatureException("Failed to encode certificates", e);
            }
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int?, sbyte[]>> digests = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int?, sbyte[]>>(signerConfig.signatureAlgorithms.Size());
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm signatureAlgorithm in signerConfig.signatureAlgorithms)
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm contentDigestAlgorithm = signatureAlgorithm.GetContentDigestAlgorithm();
                sbyte[] contentDigest = contentDigests.Get(contentDigestAlgorithm);
                if (contentDigest == null)
                {
                    throw new SigningServer.Android.Core.RuntimeException(contentDigestAlgorithm + " content digest for " + signatureAlgorithm + " not computed");
                }
                digests.Add(SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<int, sbyte[]>(signatureAlgorithm.GetId(), contentDigest));
            }
            signedData.digests = digests;
            signedData.minSdkVersion = signerConfig.minSdkVersion;
            signedData.maxSdkVersion = signerConfig.maxSdkVersion;
            signedData.additionalAttributes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.GenerateAdditionalAttributes(signerConfig);
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.V3SignatureSchemeBlock.Signer signer = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.V3SignatureSchemeBlock.Signer();
            signer.signedData = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.EncodeSignedData(signedData);
            signer.minSdkVersion = signerConfig.minSdkVersion;
            signer.maxSdkVersion = signerConfig.maxSdkVersion;
            signer.publicKey = encodedPublicKey;
            signer.signatures = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GenerateSignaturesOverData(signerConfig, signer.signedData);
            return SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.EncodeSigner(signer);
        }
        
        internal static sbyte[] EncodeSigner(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.V3SignatureSchemeBlock.Signer signer)
        {
            sbyte[] signedData = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsLengthPrefixedElement(signer.signedData);
            sbyte[] signatures = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsLengthPrefixedElement(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signer.signatures));
            sbyte[] publicKey = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsLengthPrefixedElement(signer.publicKey);
            int payloadSize = signedData.Length + 4 + 4 + signatures.Length + publicKey.Length;
            SigningServer.Android.IO.ByteBuffer result = SigningServer.Android.IO.ByteBuffer.Allocate(payloadSize);
            result.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            result.Put(signedData);
            result.PutInt(signer.minSdkVersion);
            result.PutInt(signer.maxSdkVersion);
            result.Put(signatures);
            result.Put(publicKey);
            return result.Array();
        }
        
        internal static sbyte[] EncodeSignedData(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.V3SignatureSchemeBlock.SignedData signedData)
        {
            sbyte[] digests = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsLengthPrefixedElement(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signedData.digests));
            sbyte[] certs = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsLengthPrefixedElement(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedElements(signedData.certificates));
            sbyte[] attributes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsLengthPrefixedElement(signedData.additionalAttributes);
            int payloadSize = digests.Length + certs.Length + 4 + 4 + attributes.Length;
            SigningServer.Android.IO.ByteBuffer result = SigningServer.Android.IO.ByteBuffer.Allocate(payloadSize);
            result.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            result.Put(digests);
            result.Put(certs);
            result.PutInt(signedData.minSdkVersion);
            result.PutInt(signedData.maxSdkVersion);
            result.Put(attributes);
            return result.Array();
        }
        
        internal static sbyte[] GenerateAdditionalAttributes(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig signerConfig)
        {
            if (signerConfig.mSigningCertificateLineage == null)
            {
                return new sbyte[0];
            }
            return SigningServer.Android.Com.Android.Apksig.Internal.Apk.V3.V3SchemeSigner.GenerateV3SignerAttribute(signerConfig.mSigningCertificateLineage);
        }
        
        internal class V3SignatureSchemeBlock
        {
            internal class Signer
            {
                public sbyte[] signedData;
                
                public int minSdkVersion;
                
                public int maxSdkVersion;
                
                public SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int?, sbyte[]>> signatures;
                
                public sbyte[] publicKey;
                
            }
            
            internal class SignedData
            {
                public SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int?, sbyte[]>> digests;
                
                public SigningServer.Android.Collections.List<sbyte[]> certificates;
                
                public int minSdkVersion;
                
                public int maxSdkVersion;
                
                public sbyte[] additionalAttributes;
                
            }
            
        }
        
    }
    
}
