/*
 * Copyright (C) 2020 The Android Open Source Project
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
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using static SigningServer.Android.ApkSig.Internal.Apk.ApkSigningBlockUtilsLite;

namespace SigningServer.Android.ApkSig.Internal.Apk.Stamp
{
    /** Lightweight version of the V3SigningCertificateLineage to be used for source stamps. */
    public class SourceStampCertificateLineage
    {
        private readonly static int FIRST_VERSION = 1;
        private readonly static int CURRENT_VERSION = FIRST_VERSION;

        /**
         * Deserializes the binary representation of a SourceStampCertificateLineage. Also
         * verifies that the structure is well-formed, e.g. that the signature for each node is from its
         * parent.
         */
        public static List<SigningCertificateNode> readSigningCertificateLineage(ByteBuffer inputBytes)

        {
            List<SigningCertificateNode> result = new List<SigningCertificateNode>();

            int nodeCount = 0;
            if (inputBytes == null || !inputBytes.hasRemaining())
            {
                return null;
            }

            ApkSigningBlockUtilsLite.checkByteOrderLittleEndian(inputBytes);

            // FORMAT (little endian):
            // * uint32: version code
            // * sequence of length-prefixed (uint32): nodes
            //   * length-prefixed bytes: signed data
            //     * length-prefixed bytes: certificate
            //     * uint32: signature algorithm id
            //   * uint32: flags
            //   * uint32: signature algorithm id (used by to sign next cert in lineage)
            //   * length-prefixed bytes: signature over above signed data

            X509Certificate2 lastCert = null;
            int lastSigAlgorithmId = 0;

            try
            {
                int version = inputBytes.getInt();
                if (version != CURRENT_VERSION)
                {
                    // we only have one version to worry about right now, so just check it
                    throw new ArgumentException("Encoded SigningCertificateLineage has a version"
                                                + " different than any of which we are aware");
                }

                HashSet<X509Certificate2> certHistorySet = new HashSet<X509Certificate2>();
                while (inputBytes.hasRemaining())
                {
                    nodeCount++;
                    ByteBuffer nodeBytes = getLengthPrefixedSlice(inputBytes);
                    ByteBuffer signedData = getLengthPrefixedSlice(nodeBytes);
                    int flags = nodeBytes.getInt();
                    int sigAlgorithmId = nodeBytes.getInt();
                    SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.findById(lastSigAlgorithmId);
                    byte[] signature = readLengthPrefixedByteArray(nodeBytes);

                    if (lastCert != null)
                    {
                        // Use previous level cert to verify current level
                        String jcaSignatureAlgorithm =
                            sigAlgorithm.getJcaSignatureAlgorithmAndParams().Item1;
                        AlgorithmParameterSpec jcaSignatureAlgorithmParams =
                            sigAlgorithm.getJcaSignatureAlgorithmAndParams().Item2;
                        PublicKey publicKey = lastCert.PublicKey;
                        
                        // TODO: Correct verify 
                        // Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                        // sig.initVerify(publicKey);
                        // if (jcaSignatureAlgorithmParams != null)
                        // {
                        //     sig.setParameter(jcaSignatureAlgorithmParams);
                        // }
                        //
                        // sig.update(signedData);
                        // if (!sig.verify(signature))
                        // {
                        //     throw new SecurityException("Unable to verify signature of certificate #"
                        //                                 + nodeCount + " using " + jcaSignatureAlgorithm +
                        //                                 " when verifying"
                        //                                 + " SourceStampCertificateLineage object");
                        // }
                    }

                    signedData.rewind();
                    byte[] encodedCert = readLengthPrefixedByteArray(signedData);
                    int signedSigAlgorithm = signedData.getInt();
                    if (lastCert != null && lastSigAlgorithmId != signedSigAlgorithm)
                    {
                        throw new SecurityException("Signing algorithm ID mismatch for certificate #"
                                                    + nodeBytes +
                                                    " when verifying SourceStampCertificateLineage object");
                    }

                    lastCert = new X509Certificate2(encodedCert);
                    // lastCert = new GuaranteedEncodedFormX509Certificate(lastCert, encodedCert);
                    if (certHistorySet.Contains(lastCert))
                    {
                        throw new SecurityException("Encountered duplicate entries in "
                                                    + "SigningCertificateLineage at certificate #" + nodeCount +
                                                    ".  All "
                                                    + "signing certificates should be unique");
                    }

                    certHistorySet.Add(lastCert);
                    lastSigAlgorithmId = sigAlgorithmId;
                    result.Add(new SigningCertificateNode(
                        lastCert, SignatureAlgorithm.findById(signedSigAlgorithm),
                        SignatureAlgorithm.findById(sigAlgorithmId), signature, flags));
                }
            }
            catch (Exception e) when (e is ApkFormatException || e is BufferUnderflowException)
            {
                throw new IOException("Failed to parse SourceStampCertificateLineage object", e);
            }
            catch (Exception e) when (e is CryptographicException)
            {
                throw new SecurityException(
                    "Failed to verify signature over signed data for certificate #" + nodeCount
                    + " when parsing SourceStampCertificateLineage object",
                    e);
            }

            // catch(CertificateException e){
            //     throw new SecurityException("Failed to decode certificate #" + nodeCount
            //                                                                  + " when parsing SourceStampCertificateLineage object",
            //         e);
            // }
            return result;
        }

        /**
     * Represents one signing certificate in the SourceStampCertificateLineage, which
     * generally means it is/was used at some point to sign source stamps.
     */
        public class SigningCertificateNode : IEquatable<SigningCertificateNode>
        {
            public SigningCertificateNode(
                X509Certificate2 signingCert,
                SignatureAlgorithm parentSigAlgorithm,
                SignatureAlgorithm sigAlgorithm,
                byte[] signature,
                int flags)
            {
                this.signingCert = signingCert;
                this.parentSigAlgorithm = parentSigAlgorithm;
                this.sigAlgorithm = sigAlgorithm;
                this.signature = signature;
                this.flags = flags;
            }

            public bool Equals(SigningCertificateNode other)
            {
                if (ReferenceEquals(null, other)) return false;
                if (ReferenceEquals(this, other)) return true;
                return Equals(signingCert, other.signingCert) && Equals(parentSigAlgorithm, other.parentSigAlgorithm) &&
                       Equals(sigAlgorithm, other.sigAlgorithm) && Equals(signature, other.signature) &&
                       flags == other.flags;
            }

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj)) return false;
                if (ReferenceEquals(this, obj)) return true;
                if (obj.GetType() != this.GetType()) return false;
                return Equals((SigningCertificateNode)obj);
            }

            public override int GetHashCode()
            {
                unchecked
                {
                    var hashCode = (signingCert != null ? signingCert.GetHashCode() : 0);
                    hashCode = (hashCode * 397) ^ (parentSigAlgorithm != null ? parentSigAlgorithm.GetHashCode() : 0);
                    hashCode = (hashCode * 397) ^ (sigAlgorithm != null ? sigAlgorithm.GetHashCode() : 0);
                    hashCode = (hashCode * 397) ^ (signature != null ? signature.GetHashCode() : 0);
                    hashCode = (hashCode * 397) ^ flags;
                    return hashCode;
                }
            }

            public static bool operator ==(SigningCertificateNode left, SigningCertificateNode right)
            {
                return Equals(left, right);
            }

            public static bool operator !=(SigningCertificateNode left, SigningCertificateNode right)
            {
                return !Equals(left, right);
            }

            /**
             * the signing cert for this node.  This is part of the data signed by the parent node.
             */
            public readonly X509Certificate2 signingCert;

            /**
             * the algorithm used by this node's parent to bless this data.  Its ID value is part of
             * the data signed by the parent node. {@code null} for first node.
             */
            public readonly SignatureAlgorithm parentSigAlgorithm;

            /**
             * the algorithm used by this node to bless the next node's data.  Its ID value is part
             * of the signed data of the next node. {@code null} for the last node.
             */
            public SignatureAlgorithm sigAlgorithm;

            /**
             * signature over the signed data (above).  The signature is from this node's parent
             * signing certificate, which should correspond to the signing certificate used to sign an
             * APK before rotating to this one, and is formed using {@code signatureAlgorithm}.
             */
            public readonly byte[] signature;

            /**
             * the flags detailing how the platform should treat this signing cert
             */
            public int flags;
        }
    }
}