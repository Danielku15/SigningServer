// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2
{
    /// <summary>
    /// APK Signature Scheme v2 signer.
    /// 
    /// &lt;p&gt;APK Signature Scheme v2 is a whole-file signature scheme which aims to protect every single
    /// bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
    /// uncompressed contents of ZIP entries.
    /// 
    /// @see &lt;a href="https://source.android.com/security/apksigning/v2.html"&gt;APK Signature Scheme v2&lt;/a&gt;
    /// </summary>
    public abstract class V2SchemeSigner
    {
        public static readonly int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID;
        
        /// <summary>
        /// Hidden constructor to prevent instantiation.
        /// </summary>
        internal V2SchemeSigner()
        {
        }
        
        /// <summary>
        /// Gets the APK Signature Scheme v2 signature algorithms to be used for signing an APK using the
        /// provided key.
        /// 
        /// @param minSdkVersion minimum API Level of the platform on which the APK may be installed (see
        ///     AndroidManifest.xml minSdkVersion attribute).
        /// @throws InvalidKeyException if the provided key is not suitable for signing APKs using APK
        ///     Signature Scheme v2
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
        
        public static SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SigningSchemeBlockAndDigests GenerateApkSignatureSchemeV2Block(SigningServer.Android.Com.Android.Apksig.Util.RunnablesExecutor executor, SigningServer.Android.Com.Android.Apksig.Util.DataSource beforeCentralDir, SigningServer.Android.Com.Android.Apksig.Util.DataSource centralDir, SigningServer.Android.Com.Android.Apksig.Util.DataSource eocd, SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig> signerConfigs, bool v3SigningEnabled)
        {
            return SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeSigner.GenerateApkSignatureSchemeV2Block(
                executor
                , 
                beforeCentralDir
                , 
                centralDir
                , 
                eocd
                , 
                signerConfigs
                , 
                v3SigningEnabled
                , 
                null
            
            );
        }
        
        public static SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SigningSchemeBlockAndDigests GenerateApkSignatureSchemeV2Block(SigningServer.Android.Com.Android.Apksig.Util.RunnablesExecutor executor, SigningServer.Android.Com.Android.Apksig.Util.DataSource beforeCentralDir, SigningServer.Android.Com.Android.Apksig.Util.DataSource centralDir, SigningServer.Android.Com.Android.Apksig.Util.DataSource eocd, SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig> signerConfigs, bool v3SigningEnabled, SigningServer.Android.Collections.List<sbyte[]> preservedV2SignerBlocks)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig>, SigningServer.Android.Collections.Map<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, sbyte[]>> digestInfo = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.ComputeContentDigests(executor, beforeCentralDir, centralDir, eocd, signerConfigs);
            return new SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SigningSchemeBlockAndDigests(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeSigner.GenerateApkSignatureSchemeV2Block(digestInfo.GetFirst(), digestInfo.GetSecond(), v3SigningEnabled, preservedV2SignerBlocks), digestInfo.GetSecond());
        }
        
        internal static SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<sbyte[], int> GenerateApkSignatureSchemeV2Block(SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig> signerConfigs, SigningServer.Android.Collections.Map<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, sbyte[]> contentDigests, bool v3SigningEnabled, SigningServer.Android.Collections.List<sbyte[]> preservedV2SignerBlocks)
        {
            SigningServer.Android.Collections.List<sbyte[]> signerBlocks = new SigningServer.Android.Collections.List<sbyte[]>(signerConfigs.Size());
            if (preservedV2SignerBlocks != null && preservedV2SignerBlocks.Size() > 0)
            {
                signerBlocks.AddAll(preservedV2SignerBlocks);
            }
            int signerNumber = 0;
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig signerConfig in signerConfigs)
            {
                signerNumber++;
                sbyte[] signerBlock;
                try
                {
                    signerBlock = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeSigner.GenerateSignerBlock(signerConfig, contentDigests, v3SigningEnabled);
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
            return SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<sbyte[], int>(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedElements(new sbyte[][]{
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedElements(signerBlocks)}
            ), SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID);
        }
        
        internal static sbyte[] GenerateSignerBlock(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.SignerConfig signerConfig, SigningServer.Android.Collections.Map<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ContentDigestAlgorithm, sbyte[]> contentDigests, bool v3SigningEnabled)
        {
            if (signerConfig.certificates.IsEmpty())
            {
                throw new SigningServer.Android.Security.SignatureException("No certificates configured for signer");
            }
            SigningServer.Android.Security.PublicKey publicKey = signerConfig.certificates.Get(0).GetPublicKey();
            sbyte[] encodedPublicKey = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodePublicKey(publicKey);
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeSigner.V2SignatureSchemeBlock.SignedData signedData = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeSigner.V2SignatureSchemeBlock.SignedData();
            try
            {
                signedData.certificates = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeCertificates(signerConfig.certificates);
            }
            catch (SigningServer.Android.Security.Cert.CertificateEncodingException e)
            {
                throw new SigningServer.Android.Security.SignatureException("Failed to encode certificates", e);
            }
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int, sbyte[]>> digests = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int, sbyte[]>>(signerConfig.signatureAlgorithms.Size());
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
            signedData.additionalAttributes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeSigner.GenerateAdditionalAttributes(v3SigningEnabled);
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeSigner.V2SignatureSchemeBlock.Signer signer = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeSigner.V2SignatureSchemeBlock.Signer();
            signer.signedData = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedElements(new sbyte[][]{
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signedData.digests), SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedElements(signedData.certificates), signedData.additionalAttributes, new sbyte[0]}
            );
            signer.publicKey = encodedPublicKey;
            signer.signatures = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int, sbyte[]>>();
            signer.signatures = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.GenerateSignaturesOverData(signerConfig, signer.signedData);
            return SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedElements(new sbyte[][]{
                signer.signedData, SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.EncodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signer.signatures), signer.publicKey}
            );
        }
        
        internal static sbyte[] GenerateAdditionalAttributes(bool v3SigningEnabled)
        {
            if (v3SigningEnabled)
            {
                int payloadSize = 4 + 4 + 4;
                SigningServer.Android.IO.ByteBuffer result = SigningServer.Android.IO.ByteBuffer.Allocate(payloadSize);
                result.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
                result.PutInt(payloadSize - 4);
                result.PutInt(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V2.V2SchemeConstants.STRIPPING_PROTECTION_ATTR_ID);
                result.PutInt(SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
                return result.Array();
            }
            else 
            {
                return new sbyte[0];
            }
        }
        
        internal class V2SignatureSchemeBlock
        {
            internal class Signer
            {
                public sbyte[] signedData;
                
                public SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int, sbyte[]>> signatures;
                
                public sbyte[] publicKey;
                
            }
            
            internal class SignedData
            {
                public SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<int, sbyte[]>> digests;
                
                public SigningServer.Android.Collections.List<sbyte[]> certificates;
                
                public sbyte[] additionalAttributes;
                
            }
            
        }
        
    }
    
}
