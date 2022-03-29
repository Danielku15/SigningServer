/*
 * Copyright (C) 2017 The Android Open Source Project
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

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /**
     * Utilities for byte arrays and I/O streams.
     */
    public static class ByteStreams
    {
        /**
         * Returns the data remaining in the provided input stream as a byte array
         */
        public static byte[] toByteArray(Stream @in)
        {
            var result = new MemoryStream();
            @in.CopyTo(result);
            return result.ToArray();
        }
    }
}