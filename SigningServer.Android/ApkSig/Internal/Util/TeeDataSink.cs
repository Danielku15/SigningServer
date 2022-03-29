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
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /**
     * {@link DataSink} which copies provided input into each of the sinks provided to it.
     */
    public class TeeDataSink : DataSink
    {
        private readonly DataSink[] mSinks;

        public TeeDataSink(DataSink[] sinks)
        {
            mSinks = sinks;
        }

        public void consume(byte[] buf, int offset, int length)
        {
            foreach (DataSink sink in mSinks)
            {
                sink.consume(buf, offset, length);
            }
        }

        public void consume(ByteBuffer buf)
        {
            int originalPosition = buf.position();
            for (int i = 0;
                 i < mSinks.Length;
                 i++)
            {
                if (i > 0)
                {
                    buf.position(originalPosition);
                }

                mSinks[i].consume(buf);
            }
        }
    }
}