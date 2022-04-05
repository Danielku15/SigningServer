/*
 * Copyright (C) 2018 The Android Open Source Project
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
using System.Linq;
using System.Security.Cryptography;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.v3;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;

namespace SigningServer.Android.ApkSig
{
    /**
     * APK Signer Lineage.
     *
     * <p>The signer lineage contains a history of signing certificates with each ancestor attesting to
     * the validity of its descendant.  Each additional descendant represents a new identity that can be
     * used to sign an APK, and each generation has accompanying attributes which represent how the
     * APK would like to view the older signing certificates, specifically how they should be trusted in
     * certain situations.
     *
     * <p> Its primary use is to enable APK Signing Certificate Rotation.  The Android platform verifies
     * the APK Signer Lineage, and if the current signing certificate for the APK is in the Signer
     * Lineage, and the Lineage contains the certificate the platform associates with the APK, it will
     * allow upgrades to the new certificate.
     *
     * @see <a href="https://source.android.com/security/apksigning/index.html">Application Signing</a>
     */
    public class SigningCertificateLineage
    {
        public static readonly int MAGIC = 0x3eff39d1;

        private const int FIRST_VERSION = 1;

        private const int CURRENT_VERSION = FIRST_VERSION;

        /** accept data from already installed pkg with this cert */
        private const int PAST_CERT_INSTALLED_DATA = 1;

        /** accept sharedUserId with pkg with this cert */
        private const int PAST_CERT_SHARED_USER_ID = 2;

        /** grant SIGNATURE permissions to pkgs with this cert */
        private const int PAST_CERT_PERMISSION = 4;

        /**
     * Enable updates back to this certificate.  WARNING: this effectively removes any benefit of
     * signing certificate changes, since a compromised key could retake control of an app even
     * after change, and should only be used if there is a problem encountered when trying to ditch
     * an older cert.
     */
        private const int PAST_CERT_ROLLBACK = 8;

        /**
     * Preserve authenticator module-based access in AccountManager gated by signing certificate.
     */
        private const int PAST_CERT_AUTH = 16;

        private readonly int mMinSdkVersion;

        /**
     * The signing lineage is just a list of nodes, with the first being the original signing
     * certificate and the most recent being the one with which the APK is to actually be signed.
     */
        private readonly List<V3SigningCertificateLineage.SigningCertificateNode> mSigningLineage;

        private SigningCertificateLineage(int minSdkVersion,
            List<V3SigningCertificateLineage.SigningCertificateNode> list)
        {
            mMinSdkVersion = minSdkVersion;
            mSigningLineage = list;
        }

        private static SigningCertificateLineage createSigningLineage(
            int minSdkVersion, SignerConfig parent, SignerCapabilities parentCapabilities,
            SignerConfig child, SignerCapabilities childCapabilities)
        {
            SigningCertificateLineage signingCertificateLineage =
                new SigningCertificateLineage(minSdkVersion,
                    new List<V3SigningCertificateLineage.SigningCertificateNode>());
            signingCertificateLineage =
                signingCertificateLineage.spawnFirstDescendant(parent, parentCapabilities);
            return signingCertificateLineage.spawnDescendant(parent, child, childCapabilities);
        }

        public static SigningCertificateLineage readFromBytes(byte[] lineageBytes)
        {
            return readFromDataSource(DataSources.asDataSource(ByteBuffer.wrap(lineageBytes)));
        }

        public static SigningCertificateLineage readFromFile(FileInfo file)
        {
            if (file == null)
            {
                throw new ArgumentNullException(nameof(file));
            }

            RandomAccessFile inputFile = new RandomAccessFile(file, "r");
            return readFromDataSource(DataSources.asDataSource(inputFile));
        }

        public static SigningCertificateLineage readFromDataSource(DataSource dataSource)
        {
            if (dataSource == null)
            {
                throw new ArgumentNullException(nameof(dataSource));
            }

            ByteBuffer inBuff = dataSource.getByteBuffer(0, (int)dataSource.size());
            inBuff.order(ByteOrder.LITTLE_ENDIAN);
            return read(inBuff);
        }

        /**
     * Extracts a Signing Certificate Lineage from a v3 signer proof-of-rotation attribute.
     *
     * <note>
     *     this may not give a complete representation of an APK's signing certificate history,
     *     since the APK may have multiple signers corresponding to different platform versions.
     *     Use <code> readFromApkFile</code> to handle this case.
     * </note>
     * @param attrValue
     */
        public static SigningCertificateLineage readFromV3AttributeValue(byte[] attrValue)
        {
            List<V3SigningCertificateLineage.SigningCertificateNode> parsedLineage =
                V3SigningCertificateLineage.readSigningCertificateLineage(ByteBuffer.wrap(
                    attrValue).order(ByteOrder.LITTLE_ENDIAN));
            int minSdkVersion = calculateMinSdkVersion(parsedLineage);
            return new SigningCertificateLineage(minSdkVersion, parsedLineage);
        }

        /**
     * Extracts a Signing Certificate Lineage from the proof-of-rotation attribute in the V3
     * signature block of the provided APK File.
     *
     * @throws ArgumentException if the provided APK does not contain a V3 signature block,
     * or if the V3 signature block does not contain a valid lineage.
     */
        public static SigningCertificateLineage readFromApkFile(FileInfo apkFile)
        {
            using (RandomAccessFile f = new RandomAccessFile(apkFile, "r"))
            {
                DataSource apk = DataSources.asDataSource(f, 0, f.length());
                return readFromApkDataSource(apk);
            }
        }

        /**
     * Extracts a Signing Certificate Lineage from the proof-of-rotation attribute in the V3
     * signature block of the provided APK DataSource.
     *
     * @throws ArgumentException if the provided APK does not contain a V3 signature block,
     * or if the V3 signature block does not contain a valid lineage.
     */
        public static SigningCertificateLineage readFromApkDataSource(DataSource apk)
        {
            SignatureInfo signatureInfo;
            try
            {
                ZipSections zipSections = ApkUtils.findZipSections(apk);
                ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                    ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
                signatureInfo =
                    ApkSigningBlockUtils.findSignature(apk, zipSections,
                        V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID, result);
            }
            catch (ZipFormatException e)
            {
                throw new ApkFormatException(e.Message);
            }
            catch (ApkSigningBlockUtils.SignatureNotFoundException e)
            {
                throw new ArgumentException(
                    "The provided APK does not contain a valid V3 signature block.");
            }

            // FORMAT:
            // * length-prefixed sequence of length-prefixed signers:
            //   * length-prefixed signed data
            //   * minSDK
            //   * maxSDK
            //   * length-prefixed sequence of length-prefixed signatures
            //   * length-prefixed public key
            ByteBuffer signers = ApkSigningBlockUtils.getLengthPrefixedSlice(signatureInfo.signatureBlock);
            List<SigningCertificateLineage> lineages = new List<SigningCertificateLineage>(1);
            while (signers.hasRemaining())
            {
                ByteBuffer signer = ApkSigningBlockUtils.getLengthPrefixedSlice(signers);
                ByteBuffer signedData = ApkSigningBlockUtils.getLengthPrefixedSlice(signer);
                try
                {
                    SigningCertificateLineage lineage = readFromSignedData(signedData);
                    lineages.Add(lineage);
                }
                catch (ArgumentException ignored)
                {
                    // The current signer block does not contain a valid lineage, but it is possible
                    // another block will.
                }
            }

            SigningCertificateLineage resultLineage;
            if (lineages.Count == 0)
            {
                throw new ArgumentException(
                    "The provided APK does not contain a valid lineage.");
            }
            else if (lineages.Count > 1)
            {
                resultLineage = consolidateLineages(lineages);
            }
            else
            {
                resultLineage = lineages[0];
            }

            return resultLineage;
        }

        /**
     * Extracts a Signing Certificate Lineage from the proof-of-rotation attribute in the provided
     * signed data portion of a signer in a V3 signature block.
     *
     * @throws ArgumentException if the provided signed data does not contain a valid
     * lineage.
     */
        public static SigningCertificateLineage readFromSignedData(ByteBuffer signedData)
        {
            // FORMAT:
            //   * length-prefixed sequence of length-prefixed digests:
            //   * length-prefixed sequence of certificates:
            //     * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
            //   * uint-32: minSdkVersion
            //   * uint-32: maxSdkVersion
            //   * length-prefixed sequence of length-prefixed additional attributes:
            //     * uint32: ID
            //     * (length - 4) bytes: value
            //     * uint32: Proof-of-rotation ID: 0x3ba06f8c
            //     * length-prefixed proof-of-rotation structure
            // consume the digests through the maxSdkVersion to reach the lineage in the attributes
            ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            signedData.getInt();
            signedData.getInt();
            // iterate over the additional attributes adding any lineages to the List
            ByteBuffer additionalAttributes = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            List<SigningCertificateLineage> lineages = new List<SigningCertificateLineage>(1);
            while (additionalAttributes.hasRemaining())
            {
                ByteBuffer attribute = ApkSigningBlockUtils.getLengthPrefixedSlice(additionalAttributes);
                int id = attribute.getInt();
                if (id == V3SchemeConstants.PROOF_OF_ROTATION_ATTR_ID)
                {
                    byte[] value = ByteBufferUtils.toByteArray(attribute);
                    SigningCertificateLineage lineage = readFromV3AttributeValue(value);
                    lineages.Add(lineage);
                }
            }

            SigningCertificateLineage result;
            // There should only be a single attribute with the lineage, but if there are multiple then
            // attempt to consolidate the lineages.
            if (lineages.Count == 0)
            {
                throw new ArgumentException("The signed data does not contain a valid lineage.");
            }
            else if (lineages.Count > 1)
            {
                result = consolidateLineages(lineages);
            }
            else
            {
                result = lineages[0];
            }

            return result;
        }

        public byte[] getBytes()
        {
            return write().array();
        }

        public void writeToFile(FileInfo file)
        {
            if (file == null)
            {
                throw new ArgumentNullException(nameof(file));
            }

            RandomAccessFile outputFile = new RandomAccessFile(file, "rw");
            writeToDataSink(new RandomAccessFileDataSink(outputFile));
        }

        public void writeToDataSink(DataSink dataSink)
        {
            if (dataSink == null)
            {
                throw new ArgumentNullException(nameof(dataSink));
            }

            dataSink.consume(write());
        }

        /**
     * Add a new signing certificate to the lineage.  This effectively creates a signing certificate
     * rotation event, forcing APKs which include this lineage to be signed by the new signer. The
     * flags associated with the new signer are set to a default value.
     *
     * @param parent current signing certificate of the containing APK
     * @param child new signing certificate which will sign the APK contents
     */
        public SigningCertificateLineage spawnDescendant(SignerConfig parent, SignerConfig child)
        {
            if (parent == null || child == null)
            {
                throw new NullReferenceException("can't add new descendant to lineage with null inputs");
            }

            SignerCapabilities signerCapabilities = new SignerCapabilities.Builder().build();
            return spawnDescendant(parent, child, signerCapabilities);
        }

        /**
     * Add a new signing certificate to the lineage.  This effectively creates a signing certificate
     * rotation event, forcing APKs which include this lineage to be signed by the new signer.
     *
     * @param parent current signing certificate of the containing APK
     * @param child new signing certificate which will sign the APK contents
     * @param childCapabilities flags
     */
        public SigningCertificateLineage spawnDescendant(
            SignerConfig parent, SignerConfig child, SignerCapabilities childCapabilities)
        {
            if (parent == null)
            {
                throw new ArgumentNullException(nameof(parent));
            }

            if (child == null)
            {
                throw new ArgumentNullException(nameof(child));
            }

            if (childCapabilities == null)
            {
                throw new ArgumentNullException(nameof(childCapabilities));
            }

            if (mSigningLineage.Count == 0)
            {
                throw new ArgumentException("Cannot spawn descendant signing certificate on an"
                                            + " empty SigningCertificateLineage: no parent node");
            }

            // make sure that the parent matches our newest generation (leaf node/sink)
            V3SigningCertificateLineage.SigningCertificateNode currentGeneration =
                mSigningLineage.Last();
            if (!currentGeneration.signingCert.getEncoded().SequenceEqual(parent.getCertificate().getEncoded()))
            {
                throw new ArgumentException("SignerConfig Certificate containing private key"
                                            + " to sign the new SigningCertificateLineage record does not match the"
                                            + " existing most recent record");
            }

            // create data to be signed, including the algorithm we're going to use
            SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm(parent);
            ByteBuffer prefixedSignedData = ByteBuffer.wrap(
                V3SigningCertificateLineage.encodeSignedData(
                    child.getCertificate(), signatureAlgorithm.getId()));
            prefixedSignedData.position(4);
            ByteBuffer signedDataBuffer = ByteBuffer.allocate(prefixedSignedData.remaining());
            signedDataBuffer.put(prefixedSignedData);
            byte[] signedData = signedDataBuffer.array();

            // create SignerConfig to do the signing
            List<X509Certificate> certificates = new List<X509Certificate>(1);
            certificates.Add(parent.getCertificate());
            ApkSigningBlockUtils.SignerConfig newSignerConfig =
                new ApkSigningBlockUtils.SignerConfig();
            newSignerConfig.privateKey = parent.getPrivateKey();
            newSignerConfig.certificates = certificates;
            newSignerConfig.signatureAlgorithms = new List<SignatureAlgorithm>
            {
                signatureAlgorithm
            };

            // sign it
            List<Tuple<int, byte[]>> signatures =
                ApkSigningBlockUtils.generateSignaturesOverData(newSignerConfig, signedData);

            // readonlyly, add it to our lineage
            SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.findById(signatures[0].Item1);
            byte[] signature = signatures[0].Item2;
            currentGeneration.sigAlgorithm = sigAlgorithm;
            V3SigningCertificateLineage.SigningCertificateNode childNode =
                new V3SigningCertificateLineage.SigningCertificateNode(
                    child.getCertificate(), sigAlgorithm, null,
                    signature, childCapabilities.getFlags());
            List<V3SigningCertificateLineage.SigningCertificateNode> lineageCopy =
                new List<V3SigningCertificateLineage.SigningCertificateNode>(mSigningLineage);
            lineageCopy.Add(childNode);
            return new SigningCertificateLineage(mMinSdkVersion, lineageCopy);
        }

        /**
     * The number of signing certificates in the lineage, including the current signer, which means
     * this value can also be used to V2determine the number of signing certificate rotations by
     * subtracting 1.
     */
        public int size()
        {
            return mSigningLineage.Count;
        }

        private SignatureAlgorithm getSignatureAlgorithm(SignerConfig parent)
        {
            PublicKey publicKey = parent.getCertificate().getPublicKey();

            // TODO switch to one signature algorithm selection, or add support for multiple algorithms
            List<SignatureAlgorithm> algorithms = V3SchemeSigner.getSuggestedSignatureAlgorithms(
                publicKey, mMinSdkVersion, false /* verityEnabled */,
                false /* deterministicDsaSigning */);
            return algorithms[0];
        }

        private SigningCertificateLineage spawnFirstDescendant(
            SignerConfig parent, SignerCapabilities signerCapabilities)
        {
            if (mSigningLineage.Count != 0)
            {
                throw new InvalidOperationException("SigningCertificateLineage already has its first node");
            }

            // check to make sure that the public key for the first node is acceptable for our minSdk
            try
            {
                getSignatureAlgorithm(parent);
            }
            catch (CryptographicException e)
            {
                throw new ArgumentException("Algorithm associated with first signing certificate"
                                            + " invalid on desired platform versions", e);
            }

            // create "fake" signed data (there will be no signature over it, since there is no parent
            V3SigningCertificateLineage.SigningCertificateNode firstNode =
                new V3SigningCertificateLineage.SigningCertificateNode(
                    parent.getCertificate(), null, null, new byte[0], signerCapabilities.getFlags());
            return new SigningCertificateLineage(mMinSdkVersion,
                new List<V3SigningCertificateLineage.SigningCertificateNode>
                {
                    firstNode
                });
        }

        private static SigningCertificateLineage read(ByteBuffer inputByteBuffer)
        {
            ApkSigningBlockUtils.checkByteOrderLittleEndian(inputByteBuffer);
            if (inputByteBuffer.remaining() < 8)
            {
                throw new ArgumentException(
                    "Improper SigningCertificateLineage format: insufficient data for header.");
            }

            if (inputByteBuffer.getInt() != MAGIC)
            {
                throw new ArgumentException(
                    "Improper SigningCertificateLineage format: MAGIC header mismatch.");
            }

            return read(inputByteBuffer, inputByteBuffer.getInt());
        }

        private static SigningCertificateLineage read(ByteBuffer inputByteBuffer, int version)
        {
            switch (version)
            {
                case FIRST_VERSION:
                    try
                    {
                        List<V3SigningCertificateLineage.SigningCertificateNode> nodes =
                            V3SigningCertificateLineage.readSigningCertificateLineage(
                                ApkSigningBlockUtils.getLengthPrefixedSlice(inputByteBuffer));
                        int minSdkVersion = calculateMinSdkVersion(nodes);
                        return new SigningCertificateLineage(minSdkVersion, nodes);
                    }
                    catch (ApkFormatException e)
                    {
                        // unable to get a proper length-prefixed lineage slice
                        throw new IOException("Unable to read list of signing certificate nodes in "
                                              + "SigningCertificateLineage", e);
                    }
                default:
                    throw new ArgumentException(
                        "Improper SigningCertificateLineage format: unrecognized version.");
            }
        }

        private static int calculateMinSdkVersion(List<V3SigningCertificateLineage.SigningCertificateNode> nodes)
        {
            if (nodes == null)
            {
                throw new ArgumentException("Can't calculate minimum SDK version of null nodes");
            }

            int minSdkVersion = AndroidSdkVersion.P; // lineage introduced in P
            foreach (V3SigningCertificateLineage.SigningCertificateNode node in nodes)
            {
                if (node.sigAlgorithm != null)
                {
                    int nodeMinSdkVersion = node.sigAlgorithm.getMinSdkVersion();
                    if (nodeMinSdkVersion > minSdkVersion)
                    {
                        minSdkVersion = nodeMinSdkVersion;
                    }
                }
            }

            return minSdkVersion;
        }

        private ByteBuffer write()
        {
            byte[] encodedLineage =
                V3SigningCertificateLineage.encodeSigningCertificateLineage(mSigningLineage);
            int payloadSize = 4 + 4 + 4 + encodedLineage.Length;
            ByteBuffer result = ByteBuffer.allocate(payloadSize);
            result.order(ByteOrder.LITTLE_ENDIAN);
            result.putInt(MAGIC);
            result.putInt(CURRENT_VERSION);
            result.putInt(encodedLineage.Length);
            result.put(encodedLineage);
            result.flip();
            return result;
        }

        public byte[] encodeSigningCertificateLineage()
        {
            return V3SigningCertificateLineage.encodeSigningCertificateLineage(mSigningLineage);
        }

        public List<DefaultApkSignerEngine.SignerConfig> sortSignerConfigs(
            List<DefaultApkSignerEngine.SignerConfig> signerConfigs)
        {
            if (signerConfigs == null)
            {
                throw new ArgumentNullException(nameof(signerConfigs));
            }

            // not the most elegant sort, but we expect signerConfigs to be quite small (1 or 2 signers
            // in most cases) and likely already sorted, so not worth the overhead of doing anything
            // fancier
            List<DefaultApkSignerEngine.SignerConfig> sortedSignerConfigs =
                new List<DefaultApkSignerEngine.SignerConfig>(signerConfigs.Count);
            for (int i = 0; i < mSigningLineage.Count; i++)
            {
                for (int j = 0; j < signerConfigs.Count; j++)
                {
                    DefaultApkSignerEngine.SignerConfig config = signerConfigs[j];
                    if (mSigningLineage[i].signingCert.Equals(config.getCertificates()[0]))
                    {
                        sortedSignerConfigs.Add(config);
                        break;
                    }
                }
            }

            if (sortedSignerConfigs.Count != signerConfigs.Count)
            {
                throw new ArgumentException("SignerConfigs supplied which are not present in the"
                                            + " SigningCertificateLineage");
            }

            return sortedSignerConfigs;
        }

        /**
     * Returns the SignerCapabilities for the signer in the lineage that matches the provided
     * config.
     */
        public SignerCapabilities getSignerCapabilities(SignerConfig config)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            X509Certificate cert = config.getCertificate();
            return getSignerCapabilities(cert);
        }

        /**
     * Returns the SignerCapabilities for the signer in the lineage that matches the provided
     * certificate.
     */
        public SignerCapabilities getSignerCapabilities(X509Certificate cert)
        {
            if (cert == null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            for (int i = 0; i < mSigningLineage.Count; i++)
            {
                V3SigningCertificateLineage.SigningCertificateNode lineageNode = mSigningLineage[i];
                if (lineageNode.signingCert.Equals(cert))
                {
                    int flags = lineageNode.flags;
                    return new SignerCapabilities.Builder(flags).build();
                }
            }

            // the provided signer certificate was not found in the lineage
            throw new ArgumentException("Certificate (" + cert.getSubjectDN()
                                                        + ") not found in the SigningCertificateLineage");
        }

        /**
     * Updates the SignerCapabilities for the signer in the lineage that matches the provided
     * config. Only those capabilities that have been modified through the setXX methods will be
     * updated for the signer to prevent unset default values from being applied.
     */
        public void updateSignerCapabilities(SignerConfig config, SignerCapabilities capabilities)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            X509Certificate cert = config.getCertificate();
            for (int i = 0; i < mSigningLineage.Count; i++)
            {
                V3SigningCertificateLineage.SigningCertificateNode lineageNode = mSigningLineage[i];
                if (lineageNode.signingCert.Equals(cert))
                {
                    int flags = lineageNode.flags;
                    SignerCapabilities newCapabilities = new SignerCapabilities.Builder(
                        flags).setCallerConfiguredCapabilities(capabilities).build();
                    lineageNode.flags = newCapabilities.getFlags();
                    return;
                }
            }

            // the provided signer config was not found in the lineage
            throw new ArgumentException("Certificate (" + cert.getSubjectDN()
                                                        + ") not found in the SigningCertificateLineage");
        }

        /**
     * Returns a list containing all of the certificates in the lineage.
     */
        public List<X509Certificate> getCertificatesInLineage()
        {
            List<X509Certificate> certs = new List<X509Certificate>();
            for (int i = 0; i < mSigningLineage.Count; i++)
            {
                X509Certificate cert = mSigningLineage[i].signingCert;
                certs.Add(cert);
            }

            return certs;
        }

        /**
         * Returns {@code true} if the specified config is in the lineage.
         */
        public bool isSignerInLineage(SignerConfig config)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            X509Certificate cert = config.getCertificate();
            return isCertificateInLineage(cert);
        }

        /**
         * Returns {@code true} if the specified certificate is in the lineage.
         */
        public bool isCertificateInLineage(X509Certificate cert)
        {
            if (cert == null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            for (int i = 0; i < mSigningLineage.Count; i++)
            {
                if (mSigningLineage[i].signingCert.Equals(cert))
                {
                    return true;
                }
            }

            return false;
        }

        private static int calculateDefaultFlags()
        {
            return PAST_CERT_INSTALLED_DATA | PAST_CERT_PERMISSION
                                            | PAST_CERT_SHARED_USER_ID | PAST_CERT_AUTH;
        }

        /**
     * Returns a new SigingCertificateLineage which terminates at the node corresponding to the
     * given certificate.  This is useful in the event of rotating to a new signing algorithm that
     * is only supported on some platform versions.  It enables a v3 signature to be generated using
     * this signing certificate and the shortened proof-of-rotation record from this sub lineage in
     * conjunction with the appropriate SDK version values.
     *
     * @param x509Certificate the signing certificate for which to search
     * @return A new SigningCertificateLineage if the given certificate is present.
     *
     * @throws ArgumentException if the provided certificate is not in the lineage.
     */
        public SigningCertificateLineage getSubLineage(X509Certificate x509Certificate)
        {
            if (x509Certificate == null)
            {
                throw new ArgumentNullException(nameof(x509Certificate));
            }

            for (int i = 0; i < mSigningLineage.Count; i++)
            {
                if (mSigningLineage[i].signingCert.Equals(x509Certificate))
                {
                    return new SigningCertificateLineage(
                        mMinSdkVersion, mSigningLineage.GetRange(0, i + 1));
                }
            }

            // looks like we didn't find the cert,
            throw new ArgumentException("Certificate not found in SigningCertificateLineage");
        }

        /**
     * Consolidates all of the lineages found in an APK into one lineage, which is the longest one.
     * In so doing, it also checks that all of the smaller lineages are contained in the largest,
     * and that they properly cover the desired platform ranges.
     *
     * An APK may contain multiple lineages, one for each signer, which correspond to different
     * supported platform versions.  In this event, the lineage(s) from the earlier platform
     * version(s) need to be present in the most recent (longest) one to make sure that when a
     * platform version changes.
     *
     * <note> This does not verify that the largest lineage corresponds to the most recent supported
     * platform version.  That check requires is performed during v3 verification. </note>
     */
        public static SigningCertificateLineage consolidateLineages(
            List<SigningCertificateLineage> lineages)
        {
            if (lineages == null || lineages.Count == 0)
            {
                return null;
            }

            int largestIndex = 0;
            int maxSize = 0;

            // determine the longest chain
            for (int i = 0; i < lineages.Count; i++)
            {
                int curSize = lineages[i].size();
                if (curSize > maxSize)
                {
                    largestIndex = i;
                    maxSize = curSize;
                }
            }

            List<V3SigningCertificateLineage.SigningCertificateNode> largestList =
                lineages[largestIndex].mSigningLineage;
            // make sure all other lineages fit into this one, with the same capabilities
            for (int i = 0; i < lineages.Count; i++)
            {
                if (i == largestIndex)
                {
                    continue;
                }

                List<V3SigningCertificateLineage.SigningCertificateNode> underTest = lineages[i].mSigningLineage;
                if (!underTest.Equals(largestList.GetRange(0, underTest.Count)))
                {
                    throw new ArgumentException("Inconsistent SigningCertificateLineages. "
                                                + "Not all lineages are subsets of each other.");
                }
            }

            // if we've made it this far, they all check out, so just return the largest
            return lineages[largestIndex];
        }

        /**
     * Representation of the capabilities the APK would like to grant to its old signing
     * certificates.  The {@code SigningCertificateLineage} provides two conceptual data structures.
     *   1) proof of rotation - Evidence that other parties can trust an APK's current signing
     *      certificate if they trust an older one in this lineage
     *   2) self-trust - certain capabilities may have been granted by an APK to other parties based
     *      on its own signing certificate.  When it changes its signing certificate it may want to
     *      allow the other parties to retain those capabilities.
     * {@code SignerCapabilties} provides a representation of the second structure.
     *
     * <p>Use {@link Builder} to obtain configuration instances.
     */
        public class SignerCapabilities
        {
            private readonly int mFlags;

            private readonly int mCallerConfiguredFlags;

            private SignerCapabilities(int flags)
                : this(flags, 0)
            {
            }

            private SignerCapabilities(int flags, int callerConfiguredFlags)
            {
                mFlags = flags;
                mCallerConfiguredFlags = callerConfiguredFlags;
            }

            public int getFlags()
            {
                return mFlags;
            }

            /**
             * Returns {@code true} if the capabilities of this object match those of the provided
             * object.
             */
            public bool equals(SignerCapabilities other)
            {
                return this.mFlags == other.mFlags;
            }

            /**
             * Returns {@code true} if this object has the installed data capability.
             */
            public bool hasInstalledData()
            {
                return (mFlags & PAST_CERT_INSTALLED_DATA) != 0;
            }

            /**
             * Returns {@code true} if this object has the shared UID capability.
             */
            public bool hasSharedUid()
            {
                return (mFlags & PAST_CERT_SHARED_USER_ID) != 0;
            }

            /**
             * Returns {@code true} if this object has the permission capability.
             */
            public bool hasPermission()
            {
                return (mFlags & PAST_CERT_PERMISSION) != 0;
            }

            /**
             * Returns {@code true} if this object has the rollback capability.
             */
            public bool hasRollback()
            {
                return (mFlags & PAST_CERT_ROLLBACK) != 0;
            }

            /**
             * Returns {@code true} if this object has the auth capability.
             */
            public bool hasAuth()
            {
                return (mFlags & PAST_CERT_AUTH) != 0;
            }

            /**
             * Builder of {@link SignerCapabilities} instances.
             */
            public class Builder
            {
                private int mFlags;

                private int mCallerConfiguredFlags;

                /**
                 * Constructs a new {@code Builder}.
                 */
                public Builder()
                {
                    mFlags = calculateDefaultFlags();
                }

                /**
                 * Constructs a new {@code Builder} with the initial capabilities set to the provided
                 * flags.
                 */
                public Builder(int flags)
                {
                    mFlags = flags;
                }

                /**
                 * Set the {@code PAST_CERT_INSTALLED_DATA} flag in this capabilities object.  This flag
                 * is used by the platform to determine if installed data associated with previous
                 * signing certificate should be trusted.  In particular, this capability is required to
                 * perform signing certificate rotation during an upgrade on-device.  Without it, the
                 * platform will not permit the app data from the old signing certificate to
                 * propagate to the new version.  Typically, this flag should be set to enable signing
                 * certificate rotation, and may be unset later when the app developer is satisfied that
                 * their install base is as migrated as it will be.
                 */
                public Builder setInstalledData(bool enabled)
                {
                    mCallerConfiguredFlags |= PAST_CERT_INSTALLED_DATA;
                    if (enabled)
                    {
                        mFlags |= PAST_CERT_INSTALLED_DATA;
                    }
                    else
                    {
                        mFlags &= ~PAST_CERT_INSTALLED_DATA;
                    }

                    return this;
                }

                /**
                 * Set the {@code PAST_CERT_SHARED_USER_ID} flag in this capabilities object.  This flag
                 * is used by the platform to determine if this app is willing to be sharedUid with
                 * other apps which are still signed with the associated signing certificate.  This is
                 * useful in situations where sharedUserId apps would like to change their signing
                 * certificate, but can't guarantee the order of updates to those apps.
                 */
                public Builder setSharedUid(bool enabled)
                {
                    mCallerConfiguredFlags |= PAST_CERT_SHARED_USER_ID;
                    if (enabled)
                    {
                        mFlags |= PAST_CERT_SHARED_USER_ID;
                    }
                    else
                    {
                        mFlags &= ~PAST_CERT_SHARED_USER_ID;
                    }

                    return this;
                }

                /**
                 * Set the {@code PAST_CERT_PERMISSION} flag in this capabilities object.  This flag
                 * is used by the platform to determine if this app is willing to grant SIGNATURE
                 * permissions to apps signed with the associated signing certificate.  Without this
                 * capability, an application signed with the older certificate will not be granted the
                 * SIGNATURE permissions defined by this app.  In addition, if multiple apps define the
                 * same SIGNATURE permission, the second one the platform sees will not be installable
                 * if this capability is not set and the signing certificates differ.
                 */
                public Builder setPermission(bool enabled)
                {
                    mCallerConfiguredFlags |= PAST_CERT_PERMISSION;
                    if (enabled)
                    {
                        mFlags |= PAST_CERT_PERMISSION;
                    }
                    else
                    {
                        mFlags &= ~PAST_CERT_PERMISSION;
                    }

                    return this;
                }

                /**
                 * Set the {@code PAST_CERT_ROLLBACK} flag in this capabilities object.  This flag
                 * is used by the platform to determine if this app is willing to upgrade to a new
                 * version that is signed by one of its past signing certificates.
                 *
                 * <note> WARNING: this effectively removes any benefit of signing certificate changes,
                 * since a compromised key could retake control of an app even after change, and should
                 * only be used if there is a problem encountered when trying to ditch an older cert
                 * </note>
                 */
                public Builder setRollback(bool enabled)
                {
                    mCallerConfiguredFlags |= PAST_CERT_ROLLBACK;
                    if (enabled)
                    {
                        mFlags |= PAST_CERT_ROLLBACK;
                    }
                    else
                    {
                        mFlags &= ~PAST_CERT_ROLLBACK;
                    }

                    return this;
                }

                /**
                 * Set the {@code PAST_CERT_AUTH} flag in this capabilities object.  This flag
                 * is used by the platform to determine whether or not privileged access based on
                 * authenticator module signing certificates should be granted.
                 */
                public Builder setAuth(bool enabled)
                {
                    mCallerConfiguredFlags |= PAST_CERT_AUTH;
                    if (enabled)
                    {
                        mFlags |= PAST_CERT_AUTH;
                    }
                    else
                    {
                        mFlags &= ~PAST_CERT_AUTH;
                    }

                    return this;
                }

                /**
                 * Applies the capabilities that were explicitly set in the provided capabilities object
                 * to this builder. Any values that were not set will not be applied to this builder
                 * to prevent unintentinoally setting a capability back to a default value.
                 */
                public Builder setCallerConfiguredCapabilities(SignerCapabilities capabilities)
                {
                    // The mCallerConfiguredFlags should have a bit set for each capability that was
                    // set by a caller. If a capability was explicitly set then the corresponding bit
                    // in mCallerConfiguredFlags should be set. This allows the provided capabilities
                    // to take effect for those set by the caller while those that were not set will
                    // be cleared by the bitwise and and the initial value for the builder will remain.
                    mFlags = (mFlags & ~capabilities.mCallerConfiguredFlags) |
                             (capabilities.mFlags & capabilities.mCallerConfiguredFlags);
                    return this;
                }

                /**
                 * Returns a new {@code SignerConfig} instance configured based on the configuration of
                 * this builder.
                 */
                public SignerCapabilities build()
                {
                    return new SignerCapabilities(mFlags, mCallerConfiguredFlags);
                }
            }
        }

        /**
         * Configuration of a signer.  Used to add a new entry to the {@link SigningCertificateLineage}
         *
         * <p>Use {@link Builder} to obtain configuration instances.
         */
        public class SignerConfig
        {
            private readonly PrivateKey mPrivateKey;
            private readonly X509Certificate mCertificate;

            private SignerConfig(
                PrivateKey privateKey,
                X509Certificate certificate)
            {
                mPrivateKey = privateKey;
                mCertificate = certificate;
            }

            /**
             * Returns the signing key of this signer.
             */
            public PrivateKey getPrivateKey()
            {
                return mPrivateKey;
            }

            /**
             * Returns the certificate(s) of this signer. The first certificate's public key corresponds
             * to this signer's private key.
             */
            public X509Certificate getCertificate()
            {
                return mCertificate;
            }

            /**
             * Builder of {@link SignerConfig} instances.
             */
            public class Builder
            {
                private readonly PrivateKey mPrivateKey;
                private readonly X509Certificate mCertificate;

                /**
                 * Constructs a new {@code Builder}.
                 *
                 * @param privateKey signing key
                 * @param certificate the X.509 certificate with a subject public key of the
                 * {@code privateKey}.
                 */
                public Builder(
                    PrivateKey privateKey,
                    X509Certificate certificate)
                {
                    mPrivateKey = privateKey;
                    mCertificate = certificate;
                }

                /**
                 * Returns a new {@code SignerConfig} instance configured based on the configuration of
                 * this builder.
                 */
                public SignerConfig build()
                {
                    return new SignerConfig(
                        mPrivateKey,
                        mCertificate);
                }
            }
        }

        /**
         * Builder of {@link SigningCertificateLineage} instances.
         */
        public class Builder
        {
            private readonly SignerConfig mOriginalSignerConfig;
            private readonly SignerConfig mNewSignerConfig;
            private SignerCapabilities mOriginalCapabilities;
            private SignerCapabilities mNewCapabilities;
            private int mMinSdkVersion;

            /**
             * Constructs a new {@code Builder}.
             *
             * @param originalSignerConfig first signer in this lineage, parent of the next
             * @param newSignerConfig new signer in the lineage; the new signing key that the APK will
             *                        use
             */
            public Builder(
                SignerConfig originalSignerConfig,
                SignerConfig newSignerConfig)
            {
                if (originalSignerConfig == null || newSignerConfig == null)
                {
                    throw new NullReferenceException("Can't pass null SignerConfigs when constructing a "
                                                   + "new SigningCertificateLineage");
                }

                mOriginalSignerConfig = originalSignerConfig;
                mNewSignerConfig = newSignerConfig;
            }

            /**
         * Sets the minimum Android platform version (API Level) on which this lineage is expected
         * to validate.  It is possible that newer signers in the lineage may not be recognized on
         * the given platform, but as long as an older signer is, the lineage can still be used to
         * sign an APK for the given platform.
         *
         * <note> By default, this value is set to the value for the
         * P release, since this structure was created for that release, and will also be set to
         * that value if a smaller one is specified. </note>
         */
            public Builder setMinSdkVersion(int minSdkVersion)
            {
                mMinSdkVersion = minSdkVersion;
                return this;
            }

            /**
         * Sets capabilities to give {@code mOriginalSignerConfig}. These capabilities allow an
         * older signing certificate to still be used in some situations on the platform even though
         * the APK is now being signed by a newer signing certificate.
         */
            public Builder setOriginalCapabilities(SignerCapabilities signerCapabilities)
            {
                if (signerCapabilities == null)
                {
                    throw new ArgumentNullException(nameof(signerCapabilities));
                }

                mOriginalCapabilities = signerCapabilities;
                return this;
            }

            /**
         * Sets capabilities to give {@code mNewSignerConfig}. These capabilities allow an
         * older signing certificate to still be used in some situations on the platform even though
         * the APK is now being signed by a newer signing certificate.  By default, the new signer
         * will have all capabilities, so when first switching to a new signing certificate, these
         * capabilities have no effect, but they will act as the default level of trust when moving
         * to a new signing certificate.
         */
            public Builder setNewCapabilities(SignerCapabilities signerCapabilities)
            {
                if (signerCapabilities == null)
                {
                    throw new ArgumentNullException(nameof(signerCapabilities));
                }

                mNewCapabilities = signerCapabilities;
                return this;
            }

            public SigningCertificateLineage build()
            {
                if (mMinSdkVersion < AndroidSdkVersion.P)
                {
                    mMinSdkVersion = AndroidSdkVersion.P;
                }

                if (mOriginalCapabilities == null)
                {
                    mOriginalCapabilities = new SignerCapabilities.Builder().build();
                }

                if (mNewCapabilities == null)
                {
                    mNewCapabilities = new SignerCapabilities.Builder().build();
                }

                return createSigningLineage(
                    mMinSdkVersion, mOriginalSignerConfig, mOriginalCapabilities,
                    mNewSignerConfig, mNewCapabilities);
            }
        }
    }
}