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

using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.Test.ApkSig.Util
{
    /**
     * Tests for the {@link DataSink} returned by {@link DataSinks#asDataSink(java.io.OutputStream)}.
     */
    [TestClass]
    public class DataSinkFromOutputStreamTest : DataSinkTestBase<OutputStreamDataSink>
    {
        protected override CloseableWithDataSink createDataSink()
        {
            return CloseableWithDataSink.of((OutputStreamDataSink)DataSinks.asDataSink(new MemoryStream()));
        }

        protected override ByteBuffer getContents(OutputStreamDataSink dataSink)
        {
            return ByteBuffer.wrap(((MemoryStream)dataSink.getOutputStream()).ToArray());
        }
    }
}