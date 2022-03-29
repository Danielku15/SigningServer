/*
 * Copyright (C) 2016 The Android Open Source Project
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

using System.Security.Cryptography;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /**
     * Data sink which feeds all received data into the associated {@link MessageDigest} instances. Each
     * {@code MessageDigest} instance receives the same data.
     */
    public class MessageDigestSink : DataSink
    {
        private readonly HashAlgorithm[] mMessageDigests;

        public MessageDigestSink(HashAlgorithm[] digests)
        {
            mMessageDigests = digests;
        }

        public void consume(byte[] buf, int offset, int length)
        {
            foreach (var md in
                     mMessageDigests)
            {
                md.TransformBlock(buf, offset, length, null, 0);
            }
        }

        public void consume(ByteBuffer buf)
        {
            int originalPosition = buf.position();
            foreach (var md in mMessageDigests)
            {
                // Reset the position back to the original because the previous iteration's
                // MessageDigest.update set the buffer's position to the buffer's limit.
                buf.position(originalPosition);
                md.TransformBlock(buf);
            }
        }
    }
}