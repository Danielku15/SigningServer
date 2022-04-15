// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7
{
    /// <summary>
    /// PKCS #7 {@code AlgorithmIdentifier} as specified in RFC 5652.
    /// </summary>
    [SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Class(Type = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Type.SEQUENCE)]
    public class AlgorithmIdentifier
    {
        [SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Field(Index = 0, Type = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Type.OBJECT_IDENTIFIER)]
        public string algorithm;
        
        [SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Field(Index = 1, Type = SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1Type.ANY, Optional = true)]
        public SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1OpaqueObject parameters;
        
        public AlgorithmIdentifier()
        {
        }
        
        public AlgorithmIdentifier(string algorithmOid, SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1OpaqueObject parameters)
        {
            this.algorithm = algorithmOid;
            this.parameters = parameters;
        }
        
        /// <summary>
        /// Returns the PKCS #7 {@code DigestAlgorithm} to use when signing using the specified digest
        /// algorithm.
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier GetSignerInfoDigestAlgorithmOid(SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm digestAlgorithm)
        {
            switch (digestAlgorithm.Case)
            {
                case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA1_CASE:
                    return new SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier(SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_DIGEST_SHA1, SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DerEncoder.ASN1_DER_NULL);
                case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA256_CASE:
                    return new SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier(SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_DIGEST_SHA256, SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DerEncoder.ASN1_DER_NULL);
            }
            throw new System.ArgumentException("Unsupported digest algorithm: " + digestAlgorithm);
        }
        
        /// <summary>
        /// Returns the JCA {@link Signature} algorithm and PKCS #7 {@code SignatureAlgorithm} to use
        /// when signing with the specified key and digest algorithm.
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<string, SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier> GetSignerInfoSignatureAlgorithm(SigningServer.Android.Security.PublicKey publicKey, SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm digestAlgorithm, bool deterministicDsaSigning)
        {
            string keyAlgorithm = publicKey.GetAlgorithm();
            string jcaDigestPrefixForSigAlg;
            switch (digestAlgorithm.Case)
            {
                case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA1_CASE:
                    jcaDigestPrefixForSigAlg = "SHA1";
                    break;
                case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA256_CASE:
                    jcaDigestPrefixForSigAlg = "SHA256";
                    break;
                default:
                    throw new System.ArgumentException("Unexpected digest algorithm: " + digestAlgorithm);
            }
            if ("RSA".EqualsIgnoreCase(keyAlgorithm))
            {
                return SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier>(jcaDigestPrefixForSigAlg + "withRSA", new SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier(SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_SIG_RSA, SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DerEncoder.ASN1_DER_NULL));
            }
            else if ("DSA".EqualsIgnoreCase(keyAlgorithm))
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier sigAlgId;
                switch (digestAlgorithm.Case)
                {
                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA1_CASE:
                        sigAlgId = new SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier(SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_SIG_DSA, SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DerEncoder.ASN1_DER_NULL);
                        break;
                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.DigestAlgorithm.SHA256_CASE:
                        sigAlgId = new SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier(SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_SIG_SHA256_WITH_DSA, SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DerEncoder.ASN1_DER_NULL);
                        break;
                    default:
                        throw new System.ArgumentException("Unexpected digest algorithm: " + digestAlgorithm);
                }
                string signingAlgorithmName = jcaDigestPrefixForSigAlg + (deterministicDsaSigning ? "withDetDSA" : "withDSA");
                return SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier>(signingAlgorithmName, sigAlgId);
            }
            else if ("EC".EqualsIgnoreCase(keyAlgorithm))
            {
                return SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of<string, SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier>(jcaDigestPrefixForSigAlg + "withECDSA", new SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier(SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_SIG_EC_PUBLIC_KEY, SigningServer.Android.Com.Android.Apksig.Internal.Asn1.Asn1DerEncoder.ASN1_DER_NULL));
            }
            else 
            {
                throw new SigningServer.Android.Security.InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
            }
        }
        
        public static string GetJcaSignatureAlgorithm(string digestAlgorithmOid, string signatureAlgorithmOid)
        {
            string result = SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_TO_JCA_SIGNATURE_ALG.Get(signatureAlgorithmOid);
            if (result != null)
            {
                return result;
            }
            string suffix;
            if (SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_SIG_RSA.Equals(signatureAlgorithmOid))
            {
                suffix = "RSA";
            }
            else if (SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_SIG_DSA.Equals(signatureAlgorithmOid))
            {
                suffix = "DSA";
            }
            else if (SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_SIG_EC_PUBLIC_KEY.Equals(signatureAlgorithmOid))
            {
                suffix = "ECDSA";
            }
            else 
            {
                throw new SigningServer.Android.Security.SignatureException("Unsupported JCA Signature algorithm" + " . Digest algorithm: " + digestAlgorithmOid + ", signature algorithm: " + signatureAlgorithmOid);
            }
            string jcaDigestAlg = SigningServer.Android.Com.Android.Apksig.Internal.Pkcs7.AlgorithmIdentifier.GetJcaDigestAlgorithm(digestAlgorithmOid);
            if (jcaDigestAlg.StartsWith("SHA-"))
            {
                jcaDigestAlg = "SHA" + jcaDigestAlg.SubstringIndex("SHA-".Length());
            }
            return jcaDigestAlg + "with" + suffix;
        }
        
        public static string GetJcaDigestAlgorithm(string oid)
        {
            string result = SigningServer.Android.Com.Android.Apksig.Internal.Oid.OidConstants.OID_TO_JCA_DIGEST_ALG.Get(oid);
            if (result == null)
            {
                throw new SigningServer.Android.Security.SignatureException("Unsupported digest algorithm: " + oid);
            }
            return result;
        }
        
    }
    
}
