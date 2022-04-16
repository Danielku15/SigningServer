// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp
{
    /// <summary>
    /// Lightweight version of the V3SigningCertificateLineage to be used for source stamps.
    /// </summary>
    public class SourceStampCertificateLineage
    {
        internal static readonly int FIRST_VERSION = 1;
        
        internal static readonly int CURRENT_VERSION = SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampCertificateLineage.FIRST_VERSION;
        
        /// <summary>
        /// Deserializes the binary representation of a SourceStampCertificateLineage. Also
        /// verifies that the structure is well-formed, e.g. that the signature for each node is from its
        /// parent.
        /// </summary>
        public static SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampCertificateLineage.SigningCertificateNode> ReadSigningCertificateLineage(SigningServer.Android.IO.ByteBuffer inputBytes)
        {
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampCertificateLineage.SigningCertificateNode> result = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampCertificateLineage.SigningCertificateNode>();
            int nodeCount = 0;
            if (inputBytes == null || !inputBytes.HasRemaining())
            {
                return null;
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtilsLite.CheckByteOrderLittleEndian(inputBytes);
            SigningServer.Android.Security.Cert.CertificateFactory certFactory;
            try
            {
                certFactory = SigningServer.Android.Security.Cert.CertificateFactory.GetInstance("X.509");
            }
            catch (SigningServer.Android.Security.Cert.CertificateException e)
            {
                throw new System.InvalidOperationException("Failed to obtain X.509 CertificateFactory", e);
            }
            SigningServer.Android.Security.Cert.X509Certificate lastCert = null;
            int lastSigAlgorithmId = 0;
            try
            {
                int version = inputBytes.GetInt();
                if (version != SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampCertificateLineage.CURRENT_VERSION)
                {
                    throw new System.ArgumentException("Encoded SigningCertificateLineage has a version" + " different than any of which we are aware");
                }
                SigningServer.Android.Collections.HashSet<SigningServer.Android.Security.Cert.X509Certificate> certHistorySet = new SigningServer.Android.Collections.HashSet<SigningServer.Android.Security.Cert.X509Certificate>();
                while (inputBytes.HasRemaining())
                {
                    nodeCount++;
                    SigningServer.Android.IO.ByteBuffer nodeBytes = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtilsLite.GetLengthPrefixedSlice(inputBytes);
                    SigningServer.Android.IO.ByteBuffer signedData = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtilsLite.GetLengthPrefixedSlice(nodeBytes);
                    int flags = nodeBytes.GetInt();
                    int sigAlgorithmId = nodeBytes.GetInt();
                    SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm sigAlgorithm = SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.FindById(lastSigAlgorithmId);
                    byte[] signature = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtilsLite.ReadLengthPrefixedByteArray(nodeBytes);
                    if (lastCert != null)
                    {
                        string jcaSignatureAlgorithm = sigAlgorithm.GetJcaSignatureAlgorithmAndParams().GetFirst();
                        SigningServer.Android.Security.Spec.AlgorithmParameterSpec jcaSignatureAlgorithmParams = sigAlgorithm.GetJcaSignatureAlgorithmAndParams().GetSecond();
                        SigningServer.Android.Security.PublicKey publicKey = lastCert.GetPublicKey();
                        SigningServer.Android.Security.Signature sig = SigningServer.Android.Security.Signature.GetInstance(jcaSignatureAlgorithm);
                        sig.InitVerify(publicKey);
                        if (jcaSignatureAlgorithmParams != null)
                        {
                            sig.SetParameter(jcaSignatureAlgorithmParams);
                        }
                        sig.Update(signedData);
                        if (!sig.Verify(signature))
                        {
                            throw new SigningServer.Android.Core.SecurityException("Unable to verify signature of certificate #" + nodeCount + " using " + jcaSignatureAlgorithm + " when verifying" + " SourceStampCertificateLineage object");
                        }
                    }
                    signedData.Rewind();
                    byte[] encodedCert = SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSigningBlockUtilsLite.ReadLengthPrefixedByteArray(signedData);
                    int signedSigAlgorithm = signedData.GetInt();
                    if (lastCert != null && lastSigAlgorithmId != signedSigAlgorithm)
                    {
                        throw new SigningServer.Android.Core.SecurityException("Signing algorithm ID mismatch for certificate #" + nodeBytes + " when verifying SourceStampCertificateLineage object");
                    }
                    lastCert = (SigningServer.Android.Security.Cert.X509Certificate)certFactory.GenerateCertificate(new SigningServer.Android.IO.ByteArrayInputStream(encodedCert));
                    lastCert = new SigningServer.Android.Com.Android.Apksig.Internal.Util.GuaranteedEncodedFormX509Certificate(lastCert, encodedCert);
                    if (certHistorySet.Contains(lastCert))
                    {
                        throw new SigningServer.Android.Core.SecurityException("Encountered duplicate entries in " + "SigningCertificateLineage at certificate #" + nodeCount + ".  All " + "signing certificates should be unique");
                    }
                    certHistorySet.Add(lastCert);
                    lastSigAlgorithmId = sigAlgorithmId;
                    result.Add(new SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampCertificateLineage.SigningCertificateNode(lastCert, SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.FindById(signedSigAlgorithm), SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm.FindById(sigAlgorithmId), signature, flags));
                }
            }
            catch (System.Exception e) when ( e is SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException || e is SigningServer.Android.IO.BufferUnderflowException)
            {
                throw new global::System.IO.IOException("Failed to parse SourceStampCertificateLineage object", e);
            }
            catch (System.Exception e) when ( e is SigningServer.Android.Security.NoSuchAlgorithmException || e is SigningServer.Android.Security.InvalidKeyException || e is SigningServer.Android.Security.InvalidAlgorithmParameterException || e is SigningServer.Android.Security.SignatureException)
            {
                throw new SigningServer.Android.Core.SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing SourceStampCertificateLineage object", e);
            }
            catch (SigningServer.Android.Security.Cert.CertificateException e)
            {
                throw new SigningServer.Android.Core.SecurityException("Failed to decode certificate #" + nodeCount + " when parsing SourceStampCertificateLineage object", e);
            }
            return result;
        }
        
        /// <summary>
        /// Represents one signing certificate in the SourceStampCertificateLineage, which
        /// generally means it is/was used at some point to sign source stamps.
        /// </summary>
        public class SigningCertificateNode
        {
            public SigningCertificateNode(SigningServer.Android.Security.Cert.X509Certificate signingCert, SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm parentSigAlgorithm, SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm sigAlgorithm, byte[] signature, int flags)
            {
                this.signingCert = signingCert;
                this.parentSigAlgorithm = parentSigAlgorithm;
                this.sigAlgorithm = sigAlgorithm;
                this.signature = signature;
                this.flags = flags;
            }
            
            public override bool Equals(object o)
            {
                if (this == o)
                    return true;
                if (!(o is SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampCertificateLineage.SigningCertificateNode))
                    return false;
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampCertificateLineage.SigningCertificateNode that = (SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampCertificateLineage.SigningCertificateNode)o;
                if (!signingCert.Equals(that.signingCert))
                    return false;
                if (parentSigAlgorithm != that.parentSigAlgorithm)
                    return false;
                if (sigAlgorithm != that.sigAlgorithm)
                    return false;
                if (!SigningServer.Android.Collections.Arrays.Equals(signature, that.signature))
                    return false;
                if (flags != that.flags)
                    return false;
                return true;
            }
            
            public override int GetHashCode()
            {
                int prime = 31;
                int result = 1;
                result = prime * result + ((signingCert == null) ? 0 : signingCert.GetHashCode());
                result = prime * result + ((parentSigAlgorithm == null) ? 0 : parentSigAlgorithm.GetHashCode());
                result = prime * result + ((sigAlgorithm == null) ? 0 : sigAlgorithm.GetHashCode());
                result = prime * result + SigningServer.Android.Collections.Arrays.GetHashCode(signature);
                result = prime * result + flags;
                return result;
            }
            
            /// <summary>
            /// the signing cert for this node.  This is part of the data signed by the parent node.
            /// </summary>
            public readonly SigningServer.Android.Security.Cert.X509Certificate signingCert;
            
            /// <summary>
            /// the algorithm used by this node's parent to bless this data.  Its ID value is part of
            /// the data signed by the parent node. {@code null} for first node.
            /// </summary>
            public readonly SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm parentSigAlgorithm;
            
            /// <summary>
            /// the algorithm used by this node to bless the next node's data.  Its ID value is part
            /// of the signed data of the next node. {@code null} for the last node.
            /// </summary>
            public SigningServer.Android.Com.Android.Apksig.Internal.Apk.SignatureAlgorithm sigAlgorithm;
            
            /// <summary>
            /// signature over the signed data (above).  The signature is from this node's parent
            /// signing certificate, which should correspond to the signing certificate used to sign an
            /// APK before rotating to this one, and is formed using {@code signatureAlgorithm}.
            /// </summary>
            public readonly byte[] signature;
            
            /// <summary>
            /// the flags detailing how the platform should treat this signing cert
            /// </summary>
            public int flags;
            
        }
        
    }
    
}
