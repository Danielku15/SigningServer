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
namespace SigningServer.Android.Crypto
{
    public class ContentDigestAlgorithm
    {
        /** SHA2-256 over 1 MB chunks. */
        public static readonly ContentDigestAlgorithm CHUNKED_SHA256 = new ContentDigestAlgorithm("SHA-256", 256 / 8);

        /** SHA2-512 over 1 MB chunks. */
        public static readonly ContentDigestAlgorithm CHUNKED_SHA512 = new ContentDigestAlgorithm("SHA-512", 512 / 8);

        public string JcaMessageDigestAlgorithm { get; }
        public int ChunkDigestOutputSizeBytes { get; }

        private ContentDigestAlgorithm(string jcaMessageDigestAlgorithm, int chunkDigestOutputSizeBytes)
        {
            JcaMessageDigestAlgorithm = jcaMessageDigestAlgorithm;
            ChunkDigestOutputSizeBytes = chunkDigestOutputSizeBytes;
        }

        protected bool Equals(ContentDigestAlgorithm other)
        {
            return string.Equals(JcaMessageDigestAlgorithm, other.JcaMessageDigestAlgorithm) && ChunkDigestOutputSizeBytes == other.ChunkDigestOutputSizeBytes;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((ContentDigestAlgorithm) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((JcaMessageDigestAlgorithm != null ? JcaMessageDigestAlgorithm.GetHashCode() : 0) * 397) ^ ChunkDigestOutputSizeBytes;
            }
        }
    }
}