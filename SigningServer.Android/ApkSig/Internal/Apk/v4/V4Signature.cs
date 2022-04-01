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

using System.IO;

namespace SigningServer.Android.ApkSig.Internal.Apk.v4
{
    public class V4Signature
    {
        public static readonly int CURRENT_VERSION = 2;

        public static readonly int HASHING_ALGORITHM_SHA256 = 1;
        public static readonly byte LOG2_BLOCK_SIZE_4096_BYTES = 12;

        public class HashingInfo
        {
            public readonly int hashAlgorithm; // only 1 == SHA256 supported
            public readonly byte log2BlockSize; // only 12 (block size 4096) supported now
            public readonly byte[] salt; // used exactly as in fs-verity, 32 bytes max
            public readonly byte[] rawRootHash; // salted digest of the first Merkle tree page

            public HashingInfo(int hashAlgorithm, byte log2BlockSize, byte[] salt, byte[] rawRootHash)
            {
                this.hashAlgorithm = hashAlgorithm;
                this.log2BlockSize = log2BlockSize;
                this.salt = salt;
                this.rawRootHash = rawRootHash;
            }

            public static HashingInfo fromByteArray(byte[] bytes)
            {
                ByteBuffer buffer = ByteBuffer.wrap(
                    bytes).order(ByteOrder.LITTLE_ENDIAN);
                int hashAlgorithm =
                    buffer.getInt();
                byte log2BlockSize =
                    buffer.get();
                byte[] salt = readBytes(buffer);

                byte[] rawRootHash = readBytes(buffer);
                return new HashingInfo(hashAlgorithm, log2BlockSize, salt, rawRootHash);
            }

            public byte[] toByteArray()
            {
                int size =
                    4 /*hashAlgorithm*/ + 1 /*log2BlockSize*/ + bytesSize(this.salt)
                    + bytesSize(this.rawRootHash);
                ByteBuffer buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
                buffer.putInt(this.hashAlgorithm);
                buffer.put(this.log2BlockSize);
                writeBytes(buffer, this.salt);
                writeBytes(buffer, this.rawRootHash);
                return buffer.array();
            }
        }

        public class SigningInfo
        {
            public readonly byte[] apkDigest; // used to match with the corresponding APK
            public readonly byte[] certificate; // ASN.1 DER form
            public readonly byte[] additionalData; // a free-form binary data blob
            public readonly byte[] publicKey; // ASN.1 DER, must match the certificate
            public readonly int signatureAlgorithmId; // see the APK v2 doc for the list
            public readonly byte[] signature;

            public SigningInfo(byte[] apkDigest, byte[] certificate, byte[] additionalData,
                byte[] publicKey, int signatureAlgorithmId, byte[] signature)
            {
                this.apkDigest = apkDigest;
                this.certificate = certificate;
                this.additionalData = additionalData;
                this.publicKey = publicKey;
                this.signatureAlgorithmId = signatureAlgorithmId;
                this.signature = signature;
            }

            public static SigningInfo fromByteArray(byte[] bytes)
            {
                ByteBuffer buffer = ByteBuffer.wrap(
                    bytes
                ).order(ByteOrder.LITTLE_ENDIAN);
                byte[] apkDigest = readBytes(buffer);
                byte[] certificate = readBytes(buffer);
                byte[] additionalData = readBytes(buffer);
                byte[] publicKey = readBytes(buffer);
                int signatureAlgorithmId = buffer.getInt();

                byte[] signature = readBytes(buffer);
                return new SigningInfo(apkDigest, certificate, additionalData, publicKey,
                    signatureAlgorithmId, signature);
            }

            public byte[] toByteArray()
            {
                int size =
                    bytesSize(this.apkDigest) + bytesSize(this.certificate) + bytesSize(
                        this.additionalData) + bytesSize(this.publicKey) + 4 /*signatureAlgorithmId*/
                    + bytesSize(this.signature);
                ByteBuffer buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
                writeBytes(buffer, this.apkDigest);
                writeBytes(buffer, this.certificate);
                writeBytes(buffer, this.additionalData);
                writeBytes(buffer, this.publicKey);
                buffer.putInt(this.signatureAlgorithmId);
                writeBytes(buffer, this.signature);
                return buffer.array();
            }
        }

        public readonly int version; // Always 2 for now.
        public readonly byte[] hashingInfo;
        public readonly byte[] signingInfo; // Passed as-is to the kernel. Can be retrieved later.

        public V4Signature(int version, byte[] hashingInfo, byte[] signingInfo)
        {
            this.version = version;
            this.hashingInfo = hashingInfo;
            this.signingInfo = signingInfo;
        }

        public static V4Signature readFrom(Stream stream)
        {
            int version = readIntLE(stream);
            if (version != CURRENT_VERSION)
            {
                throw new IOException("Invalid signature version.");
            }

            byte[] hashingInfo = readBytes(stream);

            byte[] signingInfo = readBytes(stream);
            return new V4Signature(version, hashingInfo, signingInfo);
        }

        public void writeTo(Stream stream)
        {
            writeIntLE(stream, this.version);
            writeBytes(stream, this.hashingInfo);
            writeBytes(stream, this.signingInfo);
        }

        public static byte[] getSignedData(long fileSize, V4Signature.HashingInfo hashingInfo,
            V4Signature.SigningInfo signingInfo)
        {
            int size =
                4 /*size*/ + 8 /*fileSize*/ + 4 /*hash_algorithm*/ + 1 /*log2_blocksize*/ + bytesSize(
                    hashingInfo.salt) + bytesSize(hashingInfo.rawRootHash) + bytesSize(
                    signingInfo.apkDigest) + bytesSize(signingInfo.certificate) + bytesSize(
                    signingInfo.additionalData);
            ByteBuffer buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(size);
            buffer.putLong(fileSize);
            buffer.putInt(hashingInfo.hashAlgorithm);
            buffer.put(hashingInfo.log2BlockSize);
            writeBytes(buffer, hashingInfo.salt);
            writeBytes(buffer, hashingInfo.rawRootHash);
            writeBytes(buffer, signingInfo.apkDigest);
            writeBytes(buffer, signingInfo.certificate);
            writeBytes(buffer, signingInfo.additionalData);
            return buffer.array();
        }

        // Utility methods.
        static int bytesSize(byte[] bytes)
        {
            return 4 /*length*/ + (bytes == null ? 0 : bytes.Length);
        }

        static void readFully(Stream stream, byte[] buffer)
        {
            int len = buffer.Length;

            int n = 0;
            while (n < len)
            {
                int count = stream.Read(buffer, n, len - n);
                if (count < 0)
                {
                    throw new EndOfStreamException();
                }

                n += count;
            }
        }

        static int readIntLE(Stream stream)
        {
            byte[] buffer = new byte[4];

            readFully(stream, buffer);
            return ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN).getInt();
        }

        static void writeIntLE(Stream stream, int v)
        {
            byte[] buffer = ByteBuffer.wrap(new byte[4]).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(v).array();

            stream.Write(buffer, 0, buffer.Length);
        }

        public static byte[] readBytes(Stream stream)
        {
            try
            {
                int size = readIntLE(stream);
                byte[] bytes = new byte[size];
                readFully(stream, bytes);
                return bytes;
            }
            catch (EndOfStreamException ignored)
            {
                return null;
            }
        }

        public static byte[] readBytes(ByteBuffer buffer)

        {
            if (buffer.remaining() < 4)
            {
                throw new EndOfStreamException();
            }

            int size = buffer.getInt();
            if (buffer.remaining() < size)
            {
                throw new EndOfStreamException();
            }

            byte[] bytes = new byte[size];

            buffer.get(bytes);
            return bytes;
        }

        public static void writeBytes(Stream stream, byte[] bytes)
        {
            if (bytes == null)
            {
                writeIntLE(stream, 0);
                return;
            }

            writeIntLE(stream, bytes.Length);
            stream.Write(bytes, 0, bytes.Length);
        }

        public static void writeBytes(ByteBuffer buffer, byte[] bytes)
        {
            if (bytes == null)
            {
                buffer.putInt(0);
                return;
            }

            buffer.putInt(bytes.Length);
            buffer.put(bytes);
        }
    }
}