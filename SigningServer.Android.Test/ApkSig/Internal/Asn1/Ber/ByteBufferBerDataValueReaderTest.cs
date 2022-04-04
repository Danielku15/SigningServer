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

using System;
using System.Runtime.CompilerServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Asn1.Ber;

namespace SigningServer.Android.Test.ApkSig.Internal.Asn1.Ber
{
    [TestClass]
    public class ByteBufferBerDataValueReaderTest : BerDataValueReaderTestBase
    {
        protected override BerDataValueReader createReader(byte[] input)
        {
            return new ByteBufferBerDataValueReader(ByteBuffer.wrap(input));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void testConstructWithNullByteBuffer()
        {
            new ByteBufferBerDataValueReader(null);
        }
    }
}