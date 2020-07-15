/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2018 Daniel Kuschny (C# port based on oreo-master)
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
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using SigningServer.Android.Crypto;
using SigningServer.Android.Zip;

namespace SigningServer.Android.Apk
{
    /// <summary>
    /// APK Signature Scheme v2 signer.
    ///
    /// APK Signature Scheme v2 is a whole-file signature scheme which aims to protect every single
    /// bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
    /// uncompressed contents of ZIP entries.
    ///
    /// <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2</a>
    /// </summary>
    /// <remarks>
    /// The two main goals of APK Signature Scheme v2 are:
    /// 1. Detect any unauthorized modifications to the APK.This is achieved by making the signature
    /// cover every byte of the APK being signed.
    /// 2. Enable much faster signature and integrity verification.This is achieved by requiring
    /// only a minimal amount of APK parsing before the signature is verified, thus completely
    ///    bypassing ZIP entry decompression and by making integrity verification parallelizable by
    /// employing a hash tree.
    ///
    ///
    /// The generated signature block is wrapped into an APK Signing Block and inserted into the
    /// original APK immediately before the start of ZIP Central Directory. This is to ensure that
    /// JAR and ZIP parsers continue to work on the signed APK. The APK Signing Block is designed for
    /// extensibility.For example, a future signature scheme could insert its signatures there as
    /// well.The contract of the APK Signing Block is that all contents outside of the block must be
    /// protected by signatures inside the block.
    /// </remarks>
    class V2SchemeSigner
    {
        private const int ContentDigestedChunkMaxSizeBytes = 1024 * 1024;

        private const int ApkSignatureSchemeV2BlockId = 0x7109871a;

        public static readonly byte[] ApkSigningBlockMagic =
        {
            0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
            0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32,
        };

        /// <summary>
        /// Signs the provided APK using APK Signature Scheme v2 and returns the APK Signing Block containing the signature.
        /// </summary>
        /// <param name="beforeCentralDir"></param>
        /// <param name="centralDir"></param>
        /// <param name="eocd"></param>
        /// <param name="signerConfig"></param>
        /// <returns></returns>
        public static byte[] GenerateApkSigningBlock(Stream beforeCentralDir, Stream centralDir, Stream eocd,
            SignerConfig signerConfig)
        {
            // Figure out which digest(s) to use for APK contents.
            ISet<ContentDigestAlgorithm> contentDigestAlgorithms = new HashSet<ContentDigestAlgorithm>();
            contentDigestAlgorithms.Add(signerConfig.SignatureAlgorithm.ContentDigestAlgorithm);

            // Ensure that, when digesting, ZIP End of Central Directory record's Central Directory
            // offset field is treated as pointing to the offset at which the APK Signing Block will
            // start.
            var centralDirOffsetForDigesting = beforeCentralDir.Length;
            var eocdBuf = new MemoryStream(new byte[(int)eocd.Length], true);
            eocd.CopyTo(eocdBuf);
            eocdBuf.Position = 0;

            ZipUtils.SetZipEocdCentralDirectoryOffset(eocdBuf, centralDirOffsetForDigesting);

            // Compute digests of APK contents.
            IDictionary<ContentDigestAlgorithm, byte[]> contentDigests; // digest algorithm ID -> digest
            try
            {
                contentDigests =
                    ComputeContentDigests(
                        contentDigestAlgorithms,
                        new[]
                        {
                            beforeCentralDir,
                            centralDir,
                            eocdBuf
                        });
            }
            catch (IOException e)
            {
                throw new IOException("Failed to read APK being signed", e);
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException("Failed to compute digests of APK", e);
            }

            // Sign the digests and wrap the signatures and signer info into an APK Signing Block.
            return GenerateApkSigningBlock(signerConfig, contentDigests);
        }

        private static long GetChunkCount(long inputSize, int chunkSize)
        {
            return (inputSize + chunkSize - 1) / chunkSize;
        }

        private static IDictionary<ContentDigestAlgorithm, byte[]> ComputeContentDigests(
            ISet<ContentDigestAlgorithm> digestAlgorithms,
            Stream[] contents)
        {
            // For each digest algorithm the result is computed as follows:
            // 1. Each segment of contents is split into consecutive chunks of 1 MB in size.
            //    The final chunk will be shorter iff the length of segment is not a multiple of 1 MB.
            //    No chunks are produced for empty (zero length) segments.
            // 2. The digest of each chunk is computed over the concatenation of byte 0xa5, the chunk's
            //    length in bytes (uint32 little-endian) and the chunk's contents.
            // 3. The output digest is computed over the concatenation of the byte 0x5a, the number of
            //    chunks (uint32 little-endian) and the concatenation of digests of chunks of all
            //    segments in-order.
            long chunkCountLong = 0;
            foreach (var input in contents)
            {
                chunkCountLong += GetChunkCount(input.Length, ContentDigestedChunkMaxSizeBytes);
            }

            if (chunkCountLong > int.MaxValue)
            {
                throw new CryptographicException("Input too long: " + chunkCountLong + " chunks");
            }

            var chunkCount = (int)chunkCountLong;
            var digestAlgorithmsArray =
                digestAlgorithms.ToArray();
            var mds = new HashAlgorithm[digestAlgorithmsArray.Length];
            var digestsOfChunks = new byte[digestAlgorithmsArray.Length][];
            var digestOutputSizes = new int[digestAlgorithmsArray.Length];
            for (var i = 0; i < digestAlgorithmsArray.Length; i++)
            {
                var digestAlgorithm = digestAlgorithmsArray[i];
                var digestOutputSizeBytes = digestAlgorithm.ChunkDigestOutputSizeBytes;
                digestOutputSizes[i] = digestOutputSizeBytes;
                var concatenationOfChunkCountAndChunkDigests =
                    new byte[5 + chunkCount * digestOutputSizeBytes];
                concatenationOfChunkCountAndChunkDigests[0] = 0x5a;
                SetUnsignedInt32LittleEndian(
                    chunkCount, concatenationOfChunkCountAndChunkDigests, 1);
                digestsOfChunks[i] = concatenationOfChunkCountAndChunkDigests;
                var jcaAlgorithm = digestAlgorithm.JcaMessageDigestAlgorithm;
                mds[i] = HashAlgorithm.Create(jcaAlgorithm);
            }

            var mdSink = new MessageDigestStream(mds);
            var chunkContentPrefix = new byte[5];
            chunkContentPrefix[0] = 0xa5;
            var chunkIndex = 0;
            // Optimization opportunity: digests of chunks can be computed in parallel. However,
            // determining the number of computations to be performed in parallel is non-trivial. This
            // depends on a wide range of factors, such as data source type (e.g., in-memory or fetched
            // from file), CPU/memory/disk cache bandwidth and latency, interconnect architecture of CPU
            // cores, load on the system from other threads of execution and other processes, size of
            // input.
            // For now, we compute these digests sequentially and thus have the luxury of improving
            // performance by writing the digest of each chunk into a pre-allocated buffer at exactly
            // the right position. This avoids unnecessary allocations, copying, and enables the final
            // digest to be more efficient because it's presented with all of its input in one go.
            foreach (var input in contents)
            {
                input.Position = 0;

                long inputOffset = 0;
                var inputRemaining = input.Length;
                while (inputRemaining > 0)
                {
                    var chunkSize =
                        (int)Math.Min(inputRemaining, ContentDigestedChunkMaxSizeBytes);
                    SetUnsignedInt32LittleEndian(chunkSize, chunkContentPrefix, 1);
                    foreach (var md in mds)
                    {
                        md.TransformBlock(chunkContentPrefix, 0, chunkContentPrefix.Length, chunkContentPrefix, 0);
                    }

                    try
                    {
                        var buf = new byte[chunkSize];
                        input.Read(buf, 0, chunkSize);
                        mdSink.Write(buf, 0, chunkSize);
                    }
                    catch (IOException e)
                    {
                        throw new IOException("Failed to read chunk #" + chunkIndex, e);
                    }

                    for (var i = 0; i < digestAlgorithmsArray.Length; i++)
                    {
                        var md = mds[i];
                        var concatenationOfChunkCountAndChunkDigests = digestsOfChunks[i];
                        var expectedDigestSizeBytes = digestOutputSizes[i];

                        md.TransformFinalBlock(new byte[0], 0, 0);
                        var hash = md.Hash;
                        var actualDigestSizeBytes = hash.Length;
                        if (actualDigestSizeBytes != expectedDigestSizeBytes)
                        {
                            throw new Exception(
                                "Unexpected output size of " + md
                                                             + " digest: " + actualDigestSizeBytes);
                        }

                        Buffer.BlockCopy(hash, 0, concatenationOfChunkCountAndChunkDigests,
                            5 + chunkIndex * expectedDigestSizeBytes, hash.Length);

                        md.Dispose();
                        var digestAlgorithm = digestAlgorithmsArray[i];
                        var jcaAlgorithm = digestAlgorithm.JcaMessageDigestAlgorithm;
                        mds[i] = HashAlgorithm.Create(jcaAlgorithm);
                    }

                    inputOffset += chunkSize;
                    inputRemaining -= chunkSize;
                    chunkIndex++;
                }
            }

            IDictionary<ContentDigestAlgorithm, byte[]> result =
                new Dictionary<ContentDigestAlgorithm, byte[]>(digestAlgorithmsArray.Length);
            for (var i = 0; i < digestAlgorithmsArray.Length; i++)
            {
                var digestAlgorithm = digestAlgorithmsArray[i];
                var concatenationOfChunkCountAndChunkDigests = digestsOfChunks[i];
                mds[i].Dispose();
                byte[] hash;
                using (var md = HashAlgorithm.Create(digestAlgorithm.JcaMessageDigestAlgorithm))
                {
                    md.TransformFinalBlock(concatenationOfChunkCountAndChunkDigests, 0,
                        concatenationOfChunkCountAndChunkDigests.Length);
                    hash = md.Hash;
                }

                result.Add(digestAlgorithm, hash);
            }

            return result;
        }

        private static byte[] GenerateApkSigningBlock(SignerConfig signerConfigs,
            IDictionary<ContentDigestAlgorithm, byte[]> contentDigests)
        {
            var apkSignatureSchemeV2Block = GenerateApkSignatureSchemeV2Block(signerConfigs, contentDigests);
            return GenerateApkSigningBlock(apkSignatureSchemeV2Block);
        }

        private static byte[] GenerateApkSigningBlock(byte[] apkSignatureSchemeV2Block)
        {
            // FORMAT:
            // uint64:  size (excluding this field)
            // repeated ID-value pairs:
            //     uint64:           size (excluding this field)
            //     uint32:           ID
            //     (size - 4) bytes: value
            // uint64:  size (same as the one above)
            // uint128: magic
            var resultSize =
                    8 // size
                    + 8 + 4 + apkSignatureSchemeV2Block.Length // v2Block as ID-value pair
                    + 8 // size
                    + 16 // magic
                ;

            var resultBuf = new byte[resultSize];
            var result = new BinaryWriter(new MemoryStream(resultBuf, true));
            long blockSizeFieldValue = resultSize - 8;
            result.Write(blockSizeFieldValue);
            long pairSizeFieldValue = 4 + apkSignatureSchemeV2Block.Length;
            result.Write(pairSizeFieldValue);
            result.Write(ApkSignatureSchemeV2BlockId);
            result.Write(apkSignatureSchemeV2Block);
            result.Write(blockSizeFieldValue);
            result.Write(ApkSigningBlockMagic);
            return resultBuf;
        }

        private static byte[] GenerateApkSignatureSchemeV2Block(
            SignerConfig signerConfigs,
            IDictionary<ContentDigestAlgorithm, byte[]> contentDigests)
        {
            // FORMAT:
            // * length-prefixed sequence of length-prefixed signer blocks.
            var signerBlocks = new List<byte[]>(1);
            var signerNumber = 0;
            signerNumber++;
            byte[] signerBlock;
            try
            {
                signerBlock = GenerateSignerBlock(signerConfigs, contentDigests);
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException("Signer #" + signerNumber + " failed", e);
            }

            signerBlocks.Add(signerBlock);

            return EncodeAsSequenceOfLengthPrefixedElements(
                new[]
                {
                    EncodeAsSequenceOfLengthPrefixedElements(signerBlocks),
                });
        }

        private static byte[] GenerateSignerBlock(SignerConfig signerConfig,
            IDictionary<ContentDigestAlgorithm, byte[]> contentDigests)
        {
            var publicKey = signerConfig.Certificates.PublicKey;
            var encodedPublicKey = EncodePublicKey(publicKey);

            var signedData = new V2SignatureSchemeBlock.SignedData();
            try
            {
                signedData.Certificate = EncodeCertificates(signerConfig.Certificates);
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException("Failed to encode certificates", e);
            }

            var digests = new List<Tuple<int, byte[]>>(1);

            var contentDigestAlgorithm =
                signerConfig.SignatureAlgorithm.ContentDigestAlgorithm;
            var contentDigest = contentDigests[contentDigestAlgorithm];
            if (contentDigest == null)
            {
                throw new Exception(
                    contentDigestAlgorithm + " content digest for " + signerConfig.SignatureAlgorithm
                    + " not computed");
            }

            digests.Add(Tuple.Create(signerConfig.SignatureAlgorithm.Id, contentDigest));
            signedData.Digests = digests;
            var signer = new V2SignatureSchemeBlock.Signer();
            // FORMAT:
            // * length-prefixed sequence of length-prefixed digests:
            //   * uint32: signature algorithm ID
            //   * length-prefixed bytes: digest of contents
            // * length-prefixed sequence of certificates:
            //   * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
            // * length-prefixed sequence of length-prefixed additional attributes:
            //   * uint32: ID
            //   * (length - 4) bytes: value
            signer.SignedData = EncodeAsSequenceOfLengthPrefixedElements(new[]
            {
                EncodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signedData.Digests),
                EncodeAsSequenceOfLengthPrefixedElements(new[] {signedData.Certificate}),
                // additional attributes
                new byte[0],
            });
            signer.PublicKey = encodedPublicKey;
            signer.Signatures = new List<Tuple<int, byte[]>>(1);
            var signatureAlgorithm = signerConfig.SignatureAlgorithm;
            {
                var digestAlgorithm = signatureAlgorithm.DigestAlgorithm;
                byte[] signatureBytes;

                var x509Key = new X509AsymmetricSecurityKey(signerConfig.Certificates);

                if (signerConfig.Certificates.PrivateKey is RSACryptoServiceProvider x)
                {
                    if (digestAlgorithm.Oid == DigestAlgorithm.SHA1.Oid)
                    {
                        var rsa = (RSA)x509Key.GetAsymmetricAlgorithm(SecurityAlgorithms.RsaSha1Signature, true);
                        signatureBytes = rsa.SignData(signer.SignedData, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                    }
                    else if (digestAlgorithm.Oid == DigestAlgorithm.SHA256.Oid)
                    {
                        var rsa = (RSA)x509Key.GetAsymmetricAlgorithm(SecurityAlgorithms.RsaSha256Signature, true);
                        signatureBytes = rsa.SignData(signer.SignedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                    else if (digestAlgorithm.Oid == DigestAlgorithm.SHA512.Oid)
                    {
                        var rsa = (RSA)x509Key.GetAsymmetricAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", true);

                        signatureBytes = rsa.SignData(signer.SignedData, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    }
                    else
                    {
                        throw new CryptographicException($"Failed to sign using {digestAlgorithm.Name} unsupproted digest");
                    }
                }
                else if (signerConfig.Certificates.PrivateKey is DSACryptoServiceProvider dsa)
                {
                    signatureBytes = dsa.SignData(signer.SignedData);
                }
                else
                {
                    throw new CryptographicException("Failed to sign using " + digestAlgorithm.Name);
                }


                switch (publicKey.Key)
                {
                    case RSACryptoServiceProvider rsaPub:
                        using (var rsa2 = new RSACryptoServiceProvider())
                        using (var hash = digestAlgorithm.CreateInstance())
                        {
                            rsa2.ImportParameters(rsaPub.ExportParameters(false));
                            if (!rsa2.VerifyData(signer.SignedData, hash, signatureBytes))
                            {
                                throw new CryptographicException("Signature did not verify");
                            }
                        }

                        break;
                    case DSACryptoServiceProvider dsaPub:
                        using (var dsa2 = new DSACryptoServiceProvider())
                        {
                            dsa2.ImportParameters(dsaPub.ExportParameters(false));
                            if (!dsa2.VerifyData(signer.SignedData, signatureBytes))
                            {
                                throw new CryptographicException("Signature did not verify");
                            }
                        }

                        break;
                    default:
                        throw new CryptographicException(
                            "Failed to verify generated " + digestAlgorithm.Name + " signature using"
                            + " public key from certificate");
                }

                signer.Signatures.Add(Tuple.Create(signatureAlgorithm.Id, signatureBytes));
            }
            // FORMAT:
            // * length-prefixed signed data
            // * length-prefixed sequence of length-prefixed signatures:
            //   * uint32: signature algorithm ID
            //   * length-prefixed bytes: signature of signed data
            // * length-prefixed bytes: public key (X.509 SubjectPublicKeyInfo, ASN.1 DER encoded)
            return EncodeAsSequenceOfLengthPrefixedElements(
                new[]
                {
                    signer.SignedData,
                    EncodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                        signer.Signatures),
                    signer.PublicKey,
                });
        }

        private static byte[] EncodeCertificates(X509Certificate certificates)
        {
            return certificates.Export(X509ContentType.Cert);
        }

        private static byte[] EncodePublicKey(PublicKey publicKey)
        {
            var rawKey = publicKey.EncodedKeyValue.RawData;

            var sequence = new DerSequence(
                new DerSequence(new DerObjectIdentifier(publicKey.Oid.Value), DerNull.Instance),
                new DerBitString(rawKey)
            );

            return sequence.GetEncoded();
        }

        private static void SetUnsignedInt32LittleEndian(int value, byte[] result, int offset)
        {
            result[offset] = (byte)(value & 0xff);
            result[offset + 1] = (byte)((value >> 8) & 0xff);
            result[offset + 2] = (byte)((value >> 16) & 0xff);
            result[offset + 3] = (byte)((value >> 24) & 0xff);
        }

        private static byte[] EncodeAsSequenceOfLengthPrefixedElements(List<byte[]> sequence)
        {
            return EncodeAsSequenceOfLengthPrefixedElements(sequence.ToArray());
        }

        private static byte[] EncodeAsSequenceOfLengthPrefixedElements(byte[][] sequence)
        {
            var payloadSize = 0;
            foreach (var element in sequence)
            {
                payloadSize += 4 + element.Length;
            }


            var buf = new byte[payloadSize];
            var writer = new BinaryWriter(new MemoryStream(buf, true));
            foreach (var element in sequence)
            {
                writer.Write(element.Length);
                writer.Write(element);
            }

            return buf;
        }

        private static byte[] EncodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
            List<Tuple<int, byte[]>> sequence)
        {
            var resultSize = 0;
            foreach (var element in sequence)
            {
                resultSize += 12 + element.Item2.Length;
            }

            var resultBuf = new byte[resultSize];
            var result = new BinaryWriter(new MemoryStream(resultBuf, true));
            foreach (var element in sequence)
            {
                var second = element.Item2;
                result.Write(8 + second.Length);
                result.Write(element.Item1);
                result.Write(second.Length);
                result.Write(second);
            }

            return resultBuf;
        }

        public static SignatureAlgorithm GetSuggestedSignatureAlgorithms(PublicKey certificatePublicKey,
            int minSdkVersion, DigestAlgorithm digestAlgorithm)
        {
            switch (certificatePublicKey.Key)
            {
                case RSACryptoServiceProvider rsa:

                    if (digestAlgorithm != null)
                    {
                        if (DigestAlgorithm.SHA256.Equals(digestAlgorithm))
                        {
                            return SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256;
                        }
                        if (DigestAlgorithm.SHA512.Equals(digestAlgorithm))
                        {
                            return SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA512;
                        }

                        throw new CryptographicException("Cannot use " + digestAlgorithm.Name + " with v2 apk signing");
                    }

                    var modulusLengthBits = rsa.KeySize;
                    if (modulusLengthBits <= 3072)
                    {
                        // 3072-bit RSA is roughly 128-bit strong, meaning SHA-256 is a good fit.
                        return SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256;
                    }
                    else
                    {
                        // Keys longer than 3072 bit need to be paired with a stronger digest to avoid the
                        // digest being the weak link. SHA-512 is the next strongest supported digest.
                        return SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA512;
                    }
                case DSACryptoServiceProvider _:
                    if (digestAlgorithm != null)
                    {
                        if (DigestAlgorithm.SHA256.Equals(digestAlgorithm))
                        {
                            return SignatureAlgorithm.DSA_WITH_SHA256;
                        }
                        throw new CryptographicException("Cannot use " + digestAlgorithm.Name + " with v2 apk signing");
                    }

                    return SignatureAlgorithm.DSA_WITH_SHA256;
            }

            throw new CryptographicException(
                "Unsupported key algorithm: " + certificatePublicKey.Key.GetType().FullName);
        }

        public class SignerConfig
        {
            public X509Certificate2 Certificates { get; set; }
            public SignatureAlgorithm SignatureAlgorithm { get; set; }
        }


        private class V2SignatureSchemeBlock
        {
            public class Signer
            {
                public byte[] SignedData { get; set; }
                public List<Tuple<int, byte[]>> Signatures { get; set; }
                public byte[] PublicKey { get; set; }
            }

            public class SignedData
            {
                public List<Tuple<int, byte[]>> Digests { get; set; }
                public byte[] Certificate { get; set; }
            }
        }
    }
}