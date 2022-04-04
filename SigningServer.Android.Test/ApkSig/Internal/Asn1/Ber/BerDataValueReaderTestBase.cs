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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Asn1.Ber;
using SigningServer.Android.Test.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Internal.Asn1.Ber
{
    /**
     * Base class for unit tests of ASN.1 BER (see {@code X.690}) data value reader implementations.
     *
     * <p>Subclasses need to provide only an implementation of {@link #createReader(byte[])} and
     * subclass-specific tests.
     */
    public abstract class BerDataValueReaderTestBase
    {
        /**
     * Returns a new reader initialized with the provided input.
     */
        protected abstract BerDataValueReader createReader(byte[] input);

        [TestMethod]
        public void testEmptyInput()
        {
            assertNull(readDataValue(""));
        }

        [TestMethod]
        public void testEndOfInput()
        {
            BerDataValueReader reader = createReader("3000"); // SEQUENCE with empty contents
            assertNotNull(reader.readDataValue());
            // End of input has been reached
            assertNull(reader.readDataValue());
            // Null should also be returned on consecutive invocations
            assertNull(reader.readDataValue());
        }

        [TestMethod]
        public void testSingleByteTagId()

        {
            BerDataValue dataValue = readDataValue("1000");
            assertEquals(BerEncoding.TAG_CLASS_UNIVERSAL, dataValue.getTagClass());
            assertFalse(dataValue.isConstructed());
            assertEquals(0x10, dataValue.getTagNumber());

            dataValue = readDataValue("3900");
            assertEquals(BerEncoding.TAG_CLASS_UNIVERSAL, dataValue.getTagClass());
            assertTrue(dataValue.isConstructed());
            assertEquals(0x19, dataValue.getTagNumber());

            dataValue = readDataValue("6700");
            assertEquals(BerEncoding.TAG_CLASS_APPLICATION, dataValue.getTagClass());
            assertTrue(dataValue.isConstructed());
            assertEquals(7, dataValue.getTagNumber());

            dataValue = readDataValue("8600");
            assertEquals(BerEncoding.TAG_CLASS_CONTEXT_SPECIFIC, dataValue.getTagClass());
            assertFalse(dataValue.isConstructed());
            assertEquals(6, dataValue.getTagNumber());

            dataValue = readDataValue("fe00");
            assertEquals(BerEncoding.TAG_CLASS_PRIVATE, dataValue.getTagClass());
            assertTrue(dataValue.isConstructed());
            assertEquals(0x1e, dataValue.getTagNumber());
        }

        [TestMethod]
        public void testHighTagNumber()

        {
            assertEquals(7, readDataValue("3f0700").getTagNumber());
            assertEquals(7, readDataValue("3f800700").getTagNumber());
            assertEquals(7, readDataValue("3f80800700").getTagNumber());
            assertEquals(7, readDataValue("3f8080800700").getTagNumber());
            assertEquals(7, readDataValue("3f808080808080808080808080808080800700").getTagNumber());
            assertEquals(375, readDataValue("3f827700").getTagNumber());
            assertEquals(268435455, readDataValue("3fffffff7f00").getTagNumber());
            assertEquals(int.MaxValue, readDataValue("3f87ffffff7f00").getTagNumber());
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testHighTagNumberTooLarge()
        {
            readDataValue("3f888080800000"); // Integer.MAX_VALUE + 1
        }

        // [TestMethod](expected = BerDataValueFormatException.class)
        public void testTruncatedHighTagNumberLastOctetMissing()
        {
            readDataValue("9f80"); // terminating octet must not have the highest bit set
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testTruncatedBeforeFirstLengthOctet()
        {
            readDataValue("30");
        }

        [TestMethod]
        public void testShortFormLength()

        {
            assertByteBufferEquals(ByteBuffer.wrap(Array.Empty<byte>()), readDataValue("3000").getEncodedContents());
            assertByteBufferEquals(
                ByteBuffer.wrap(TestHelpers.decodeHex("010203")), readDataValue("3003010203").getEncodedContents());
        }

        [TestMethod]
        public void testLongFormLength()

        {
            assertByteBufferEquals(ByteBuffer.wrap(Array.Empty<byte>()), readDataValue("308100").getEncodedContents());
            assertByteBufferEquals(
                ByteBuffer.wrap(TestHelpers.decodeHex("010203")), readDataValue("30820003010203").getEncodedContents());
            assertEquals(
                255,
                readDataValue(concat(TestHelpers.decodeHex("3081ff"), new byte[255]))
                    .getEncodedContents().remaining());
            assertEquals(
                0x110,
                readDataValue(concat(TestHelpers.decodeHex("30820110"), new byte[0x110]))
                    .getEncodedContents().remaining());
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testTruncatedLongFormLengthBeforeFirstLengthByte()
        {
            readDataValue("3081");
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testTruncatedLongFormLengthLastLengthByteMissing()
        {
            readDataValue("308200");
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testLongFormLengthTooLarge()
        {
            readDataValue("3084ffffffff");
        }

        [TestMethod]
        public void testIndefiniteFormLength()

        {
            assertByteBufferEquals(ByteBuffer.wrap(Array.Empty<byte>()),
                readDataValue("30800000").getEncodedContents());
            assertByteBufferEquals(
                ByteBuffer.wrap(TestHelpers.decodeHex("020103")), readDataValue("30800201030000").getEncodedContents());
            assertByteBufferEquals(
                ByteBuffer.wrap(TestHelpers.decodeHex(
                    "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f")),
                readDataValue(
                    "0280"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "000102030405060708090a0b0c0d0e0f"
                    + "0000"
                ).getEncodedContents());
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testDefiniteLengthContentsTruncatedBeforeFirstContentOctet()
        {
            readDataValue("3001");
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testIndefiniteLengthContentsTruncatedBeforeFirstContentOctet()
        {
            readDataValue("3080");
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testTruncatedDefiniteLengthContents()
        {
            readDataValue("30030102");
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testTruncatedIndefiniteLengthContents()
        {
            readDataValue("308001020300");
        }

        [TestMethod]
        public void testEmptyDefiniteLengthContents()

        {
            assertByteBufferEquals(ByteBuffer.wrap(Array.Empty<byte>()), readDataValue("3000").getEncodedContents());
        }

        [TestMethod]
        public void testEmptyIndefiniteLengthContents()

        {
            assertByteBufferEquals(ByteBuffer.wrap(Array.Empty<byte>()),
                readDataValue("30800000").getEncodedContents());
        }

        [TestMethod]
        public void testPrimitiveIndefiniteLengthContentsMustNotBeParsed()

        {
            // INTEGER (0x0203) followed by 0x010000. This could be misinterpreted as INTEGER
            // (0x0203000001) if the contents of the original INTEGER are parsed to find the 0x00 0x00
            // indefinite length terminator. Such parsing must not take place for primitive (i.e., not
            // constructed) values.
            assertEquals(
                "0203",
                TestHelpers.encodeHex(readDataValue("028002030000010000").getEncodedContents()));
        }

        [TestMethod]
        public void testConstructedIndefiniteLengthContentsContainingIndefiniteLengthEncodedValues()

        {
            // Indefinite length SEQUENCE containing elements which themselves use indefinite length
            // encoding, followed by INTEGER (0x0e).
            assertEquals(
                "3080028001000000000280020000",
                TestHelpers.encodeHex(readDataValue(
                    "30803080028001000000000280020000000002010c").getEncodedContents()));
        }

        [TestMethod]
        [ExpectedException(typeof(BerDataValueFormatException))]
        public void testConstructedIndefiniteLengthContentsContainingGarbage()
        {
            // Indefinite length SEQUENCE containing truncated data value. Parsing is expected to fail
            // because the value of the sequence must be parsed (and this will fail because of garbage)
            // to establish where to look for the 0x00 0x00 indefinite length terminator of the
            // SEQUENCE.
            readDataValue("3080020a030000");
        }

        [TestMethod]
        public void testReadAdvancesPosition()

        {
            BerDataValueReader reader = createReader("37018f050001020304");
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("37018f")), reader.readDataValue().getEncoded());
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("0500")), reader.readDataValue().getEncoded());
            assertByteBufferEquals(ByteBuffer.wrap(TestHelpers.decodeHex("01020304")), reader.readDataValue().getEncoded());
            assertNull(reader.readDataValue());
        }

        private BerDataValueReader createReader(String hexEncodedInput)
        {
            return createReader(TestHelpers.decodeHex(hexEncodedInput));
        }

        private BerDataValue readDataValue(byte[] input)
        {
            return createReader(input).readDataValue();
        }

        private BerDataValue readDataValue(String hexEncodedInput)
        {
            return createReader(hexEncodedInput).readDataValue();
        }

        private static byte[] concat(byte[] arr1, byte[] arr2)
        {
            byte[] result = new byte[arr1.Length + arr2.Length];
            Array.Copy(arr1, 0, result, 0, arr1.Length);
            Array.Copy(arr2, 0, result, arr1.Length, arr2.Length);
            return result;
        }
    }
}