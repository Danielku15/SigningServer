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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Asn1.Ber;
using SigningServer.Android.Test.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Internal.Asn1.Ber
{
    [TestClass]
    public class BerDataValueTest
    {
        private static readonly BerDataValue TEST_VALUE1 =
            new BerDataValue(
                ByteBuffer.wrap(TestHelpers.decodeHex("aa")),
                ByteBuffer.wrap(TestHelpers.decodeHex("bb")),
                BerEncoding.TAG_CLASS_UNIVERSAL,
                true,
                BerEncoding.TAG_NUMBER_SEQUENCE);

        private static readonly BerDataValue TEST_VALUE2 =
            new BerDataValue(
                ByteBuffer.wrap(TestHelpers.decodeHex("cc")),
                ByteBuffer.wrap(TestHelpers.decodeHex("dd")),
                BerEncoding.TAG_CLASS_CONTEXT_SPECIFIC,
                false,
                BerEncoding.TAG_NUMBER_OCTET_STRING);

        [TestMethod]
        public void testGetTagClass()
        {
            assertEquals(BerEncoding.TAG_CLASS_UNIVERSAL, TEST_VALUE1.getTagClass());
            assertEquals(BerEncoding.TAG_CLASS_CONTEXT_SPECIFIC, TEST_VALUE2.getTagClass());
        }

        [TestMethod]
        public void testIsConstructed()
        {
            assertTrue(TEST_VALUE1.isConstructed());
            assertFalse(TEST_VALUE2.isConstructed());
        }

        [TestMethod]
        public void testGetTagNumber()
        {
            assertEquals(BerEncoding.TAG_NUMBER_SEQUENCE, TEST_VALUE1.getTagNumber());
            assertEquals(BerEncoding.TAG_NUMBER_OCTET_STRING, TEST_VALUE2.getTagNumber());
        }

        [TestMethod]
        public void testGetEncoded()
        {
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("aa")), TEST_VALUE1.getEncoded());
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("cc")), TEST_VALUE2.getEncoded());
        }

        [TestMethod]
        public void testGetEncodedReturnsSlice()
        {
            // Assert that changing the position of returned ByteBuffer does not affect ByteBuffers
            // returned in the future
            ByteBuffer encoded = TEST_VALUE1.getEncoded();
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("aa")), encoded);
            encoded.position(encoded.limit());
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("aa")), TEST_VALUE1.getEncoded());
        }

        [TestMethod]
        public void testGetEncodedContents()
        {
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("bb")), TEST_VALUE1.getEncodedContents());
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("dd")), TEST_VALUE2.getEncodedContents());
        }

        [TestMethod]
        public void testGetEncodedContentsReturnsSlice()
        {
            // Assert that changing the position of returned ByteBuffer does not affect ByteBuffers
            // returned in the future
            ByteBuffer encoded = TEST_VALUE1.getEncodedContents();
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("bb")), encoded);
            encoded.position(encoded.limit());
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("bb")), TEST_VALUE1.getEncodedContents());
        }

        [TestMethod]
        public void testDataValueReader()
        {
            BerDataValueReader reader = TEST_VALUE1.dataValueReader();
            assertSame(TEST_VALUE1, reader.readDataValue());
            assertNull(reader.readDataValue());
            assertNull(reader.readDataValue());
        }

        [TestMethod]
        public void testContentsReader()
        {
            BerDataValue dataValue =
                new BerDataValue(
                    ByteBuffer.allocate(0),
                    ByteBuffer.wrap(TestHelpers.decodeHex("300203040500")),
                    BerEncoding.TAG_CLASS_UNIVERSAL,
                    true,
                    BerEncoding.TAG_NUMBER_SEQUENCE);
            BerDataValueReader reader = dataValue.contentsReader();
            assertEquals(typeof(ByteBufferBerDataValueReader), reader.GetType());
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("30020304")),
                reader.readDataValue().getEncoded());
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("0500")), reader.readDataValue().getEncoded());
            assertNull(reader.readDataValue());
        }
    }
}