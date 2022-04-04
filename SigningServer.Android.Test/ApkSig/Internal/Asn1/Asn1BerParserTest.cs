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
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.AccessControl;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.Test.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Internal.Asn1
{
    [TestClass]
    public class Asn1BerParserTest
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void testNullInput()
        {
            parse<EmptySequence>((ByteBuffer)null);
        }

        [TestMethod]
        [ExpectedException(typeof(Asn1DecodingException))]
        public void testEmptyInput()
        {
            parse<EmptySequence>("");
        }

        [TestMethod]
        public void testEmptySequence()

        {
            // Empty SEQUENCE (0x3000) followed by garbage (0x12345678)
            ByteBuffer input = ByteBuffer.wrap(decodeHex("300012345678"));
            EmptySequence container = parse<EmptySequence>(input);
            assertNotNull(container);
            // Check that input position has been advanced appropriately
            assertEquals(2, input.position());
        }

        [TestMethod]
        public void testOctetString()

        {
            assertEquals(
                "123456", encodeHex(parse<SequenceWithOctetString>("30050403123456").buf));
            assertEquals(
                "", encodeHex(parse<SequenceWithOctetString>("30020400").buf));
        }

        [TestMethod]
        public void testBitString()

        {
            assertEquals(
                "123456", encodeHex(parse<SequenceWithBitString>("30050303123456").buf));
            assertEquals(
                "", encodeHex(parse<SequenceWithBitString>("30020300").buf));
        }

        [TestMethod]
        public void testBoolean()

        {
            assertEquals(false, parse<SequenceWithBoolean>("3003010100").value);
            assertEquals(true, parse<SequenceWithBoolean>("3003010101").value);
            assertEquals(true, parse<SequenceWithBoolean>("30030101FF").value);
        }

        [TestMethod]
        public void testUTCTime()

        {
            assertEquals("1212211221Z",
                parse<SequenceWithUTCTime>("300d170b313231323231313232315a").value);
            assertEquals("9912312359Z",
                parse<SequenceWithUTCTime>("300d170b393931323331323335395a").value);
        }

        [TestMethod]
        public void testGeneralizedTime()

        {
            assertEquals("201212211220.999-07",
                parse<SequenceWithGeneralizedTime>("301518133230313231323231313232302e3939392d3037").value);
            assertEquals("20380119031407.000+00",
                parse<SequenceWithGeneralizedTime>("3017181532303338303131393033313430372e3030302b3030").value);
        }

        [TestMethod]
        public void testInteger()

        {
            // Various Java types decoded from INTEGER
            // Empty SEQUENCE (0x3000) followed by garbage (0x12345678)
            SequenceWithIntegers container =
                parse<SequenceWithIntegers>("301e"
                                            + "0201ff" // -1
                                            + "0207ff123456789abc" // -7f123456789abc
                                            + "0200" // 0
                                            + "020280ff" // -255
                                            + "020a00000000000000001234" // 0x1234
                );
            assertEquals(-1, container.n1);
        }

        [TestMethod]
        public void testOid()

        {
            // Empty OID
            try
            {
                parse<SequenceWithOid>("30020600");
                fail();
            }
            catch (Asn1DecodingException expected)
            {
            }


            assertEquals("2.100.3", parse<SequenceWithOid>("30050603813403").oid);
            assertEquals(
                "2.16.840.1.101.3.4.2.1",
                parse<SequenceWithOid>("300b0609608648016503040201").oid);
        }

        [TestMethod]
        public void testSequenceOf()

        {
            assertEquals(2, parse<SequenceWithSequenceOf>("3006300430003000").values.Count);
        }

        [TestMethod]
        public void testSetOf()

        {
            assertEquals(2, parse<SequenceWithSetOf>("3006310430003000").values.Count);
        }

        [TestMethod]
        public void testUnencodedContainer()

        {
            SequenceWithSequenceOfUnencodedContainers seq =
                parse<SequenceWithSequenceOfUnencodedContainers>("300C300A31023000310430003000");
            assertEquals(2, seq.containers.Count);
            assertEquals(1, seq.containers[0].values.Count);
            assertEquals(2, seq.containers[1].values.Count);
        }

        [TestMethod]
        public void testImplicitOptionalField()
        {
            // Optional field f2 missing in the input
            SequenceWithImplicitOptionalField seq =
                parse<SequenceWithImplicitOptionalField>("300602010d02012a");
            assertEquals(13, seq.f1.Value);
            assertNull(seq.f2);
            assertEquals(42, seq.f3.Value);

            // Optional field f2 present in the input
            seq = parse<SequenceWithImplicitOptionalField>("300a02010da102ffff02012a");
            assertEquals(13, seq.f1.Value);
            assertEquals(-1, seq.f2.Value);
            assertEquals(42, seq.f3.Value);
        }


        [TestMethod]
        public void testExplicitOptionalField()

        {
            // Optional field f2 missing in the input
            SequenceWithExplicitOptionalField seq =
                parse<SequenceWithExplicitOptionalField>("300602010d02012a");
            assertEquals(13, seq.f1.Value);
            assertNull(seq.f2);
            assertEquals(42, seq.f3.Value);

            // Optional field f2 present in the input
            seq = parse<SequenceWithExplicitOptionalField>("300c02010da1040202ffff02012a");
            assertEquals(13, seq.f1.Value);
            assertEquals(-1, seq.f2.Value);
            assertEquals(42, seq.f3.Value);
        }

        [TestMethod]
        public void testChoiceWithDifferentTypedOptions()

        {
            // The CHOICE can be either an INTEGER or an OBJECT IDENTIFIER

            // INTEGER
            ChoiceWithTwoOptions c = parse<ChoiceWithTwoOptions>("0208ffffffffffffffff");
            assertNull(c.oid);
            assertEquals(-1, c.num.Value);

            // OBJECT IDENTIFIER
            c = parse<ChoiceWithTwoOptions>("060100");
            assertEquals("0.0", c.oid);
            assertNull(c.num);

            // Empty input
            try
            {
                parse<ChoiceWithTwoOptions>("");
                fail();
            }
            catch (Asn1DecodingException expected)
            {
            }

            // Neither of the options match
            try
            {
                // Empty SEQUENCE
                parse<ChoiceWithTwoOptions>("3000");
                fail();
            }
            catch (Asn1DecodingException expected)
            {
            }
        }

        [TestMethod]
        public void testChoiceWithSameTypedOptions()
        {
            // The CHOICE can be either a SEQUENCE, an IMPLICIT SEQUENCE, or an EXPLICIT SEQUENCE

            // SEQUENCE
            ChoiceWithThreeSequenceOptions c = parse<ChoiceWithThreeSequenceOptions>("3000");
            assertNotNull(c.s1);
            assertNull(c.s2);
            assertNull(c.s3);

            // IMPLICIT [0] SEQUENCE
            c = parse<ChoiceWithThreeSequenceOptions>("a000");
            assertNull(c.s1);
            assertNotNull(c.s2);
            assertNull(c.s3);

            // EXPLICIT [0] SEQUENCE
            c = parse<ChoiceWithThreeSequenceOptions>("a1023000");
            assertNull(c.s1);
            assertNull(c.s2);
            assertNotNull(c.s3);

            // INTEGER -- None of the options match
            try
            {
                parse<ChoiceWithThreeSequenceOptions>("02010a");
                fail();
            }
            catch (Asn1DecodingException expected)
            {
            }
        }

        [TestMethod]
        [ExpectedException(typeof(Asn1DecodingException))]
        public void testChoiceWithClashingOptions()
        {
            // The CHOICE is between INTEGER and INTEGER which clash
            parse<ChoiceWithClashingOptions>("0200");
        }

        [TestMethod]
        public void testPrimitiveIndefiniteLengthEncodingWithGarbage()

        {
            // Indefinite length INTEGER containing what may look like a malformed definite length
            // INTEGER, followed by an INTEGER. This tests that contents of indefinite length encoded
            // primitive (i.e., not constructed) data values must not be parsed to locate the 0x00 0x00
            // terminator.
            ByteBuffer input = ByteBuffer.wrap(decodeHex("0280020401000002010c"));
            ChoiceWithTwoOptions c = parse<ChoiceWithTwoOptions>(input);
            // Check what's remaining in the input buffer
            assertEquals("02010c", encodeHex(input));
            // Check what was consumed
            assertEquals(0x020401, c.num.Value);

            // Indefinite length INTEGER containing what may look like a malformed indefinite length
            // INTEGER, followed by an INTEGER
            input = ByteBuffer.wrap(decodeHex("0280028001000002010c"));
            c = parse<ChoiceWithTwoOptions>(input);
            // Check what's remaining in the input buffer
            assertEquals("02010c", encodeHex(input));
            // Check what was consumed
            assertEquals(0x028001, c.num.Value);
        }

        [TestMethod]
        public void testConstructedIndefiniteLengthEncodingWithoutNestedIndefiniteLengthDataValues()

        {
            // Indefinite length SEQUENCE containing an INTEGER whose encoding contains 0x00 0x00 which
            // can be misinterpreted as indefinite length encoding terminator of the SEQUENCE, followed
            // by an INTEGER
            ByteBuffer input = ByteBuffer.wrap(decodeHex("308002020000000002010c"));
            SequenceWithAsn1Opaque c = parse<SequenceWithAsn1Opaque>(input);
            // Check what's remaining in the input buffer
            assertEquals("02010c", encodeHex(input));
            // Check what was read
            assertEquals("02020000", encodeHex(c.obj.getEncoded()));
        }

        [TestMethod]
        public void testConstructedIndefiniteLengthEncodingWithNestedIndefiniteLengthDataValues()

        {
            // Indefinite length SEQUENCE containing two INTEGER fields using indefinite
            // length encoding, followed by an INTEGER. This tests that the 0x00 0x00 terminators used
            // by the encoding of the two INTEGERs are not confused for the 0x00 0x00 terminator of the
            // SEQUENCE.
            ByteBuffer input =
                ByteBuffer.wrap(decodeHex("308002800300000280030000020103000002010c"));
            SequenceWithAsn1Opaque c = parse<SequenceWithAsn1Opaque>(input);
            // Check what's remaining in the input buffer
            assertEquals("02010c", encodeHex(input));
            // Check what was consumed
            assertEquals("0280030000", encodeHex(c.obj.getEncoded()));
        }

        [TestMethod]
        [ExpectedException(typeof(Asn1DecodingException))]
        public void testConstructedIndefiniteLengthEncodingWithGarbage()
        {
            // Indefinite length SEQUENCE containing an indefinite length encoded SEQUENCE containing
            // garbage which doesn't parse as BER, followed by an INTEGER. This tests that contents of
            // the SEQUENCEs must be parsed to establish where their 0x00 0x00 terminators are located.
            ByteBuffer input = ByteBuffer.wrap(decodeHex("3080308002040000000002010c"));
            parse<SequenceWithAsn1Opaque>(input);
        }

        private static T parse<T>(String hexEncodedInput)
        {
            ByteBuffer input =
                (hexEncodedInput == null)
                    ? null
                    : ByteBuffer.wrap(decodeHex(hexEncodedInput));
            return parse<T>(input);
        }

        private static T parse<T>(ByteBuffer input)
        {
            return Asn1BerParser.parse<T>(input);
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class EmptySequence
        {
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithIntegers
        {
            [Asn1Field(Index = 1, Type = Asn1Type.INTEGER)]
            public int n1;

            [Asn1Field(Index = 2, Type = Asn1Type.INTEGER)]
            public long n2;

            [Asn1Field(Index = 3, Type = Asn1Type.INTEGER)]
            public int? n3;

            [Asn1Field(Index = 4, Type = Asn1Type.INTEGER)]
            public long? n4;

            [Asn1Field(Index = 5, Type = Asn1Type.INTEGER)]
            public BigInteger? n5;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithOid
        {
            [Asn1Field(Index = 0, Type = Asn1Type.OBJECT_IDENTIFIER)]
            public String oid;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithImplicitOptionalField
        {
            [Asn1Field(Index = 1, Type = Asn1Type.INTEGER)]
            public int? f1;

            [Asn1Field(Index = 2, Type = Asn1Type.INTEGER, Optional = true,
                Tagging = Asn1Tagging.IMPLICIT, TagNumber = 1)]
            public int? f2;

            [Asn1Field(Index = 3, Type = Asn1Type.INTEGER)]
            public int? f3;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithExplicitOptionalField
        {
            [Asn1Field(Index = 1, Type = Asn1Type.INTEGER)]
            public int? f1;

            [Asn1Field(Index = 2, Type = Asn1Type.INTEGER, Optional = true,
                Tagging = Asn1Tagging.EXPLICIT, TagNumber = 1)]
            public int? f2;

            [Asn1Field(Index = 3, Type = Asn1Type.INTEGER)]
            public int? f3;
        }

        [Asn1Class(Type = Asn1Type.CHOICE)]
        public class ChoiceWithTwoOptions
        {
            [Asn1Field(Type = Asn1Type.OBJECT_IDENTIFIER)]
            public String oid;

            [Asn1Field(Type = Asn1Type.INTEGER)] public int? num;
        }

        [Asn1Class(Type = Asn1Type.CHOICE)]
        public class ChoiceWithThreeSequenceOptions
        {
            [Asn1Field(Type = Asn1Type.SEQUENCE)] public EmptySequence s1;

            [Asn1Field(Type = Asn1Type.SEQUENCE, Tagging = Asn1Tagging.IMPLICIT, TagNumber = 0)]
            public EmptySequence s2;

            [Asn1Field(Type = Asn1Type.SEQUENCE, Tagging = Asn1Tagging.EXPLICIT, TagNumber = 1)]
            public EmptySequence s3;
        }

        [Asn1Class(Type = Asn1Type.CHOICE)]
        public class ChoiceWithClashingOptions
        {
            [Asn1Field(Type = Asn1Type.INTEGER)] public int n1;

            [Asn1Field(Type = Asn1Type.INTEGER)] public int? n2;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithOctetString
        {
            [Asn1Field(Index = 0, Type = Asn1Type.OCTET_STRING)]
            public ByteBuffer buf;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithBitString
        {
            [Asn1Field(Index = 0, Type = Asn1Type.BIT_STRING)]
            public ByteBuffer buf;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithSequenceOf
        {
            [Asn1Field(Index = 0, Type = Asn1Type.SEQUENCE_OF)]
            public List<EmptySequence> values;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithSetOf
        {
            [Asn1Field(Index = 0, Type = Asn1Type.SET_OF)]
            public List<EmptySequence> values;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithAsn1Opaque
        {
            [Asn1Field(Type = Asn1Type.ANY)] public Asn1OpaqueObject obj;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithSequenceOfUnencodedContainers
        {
            [Asn1Field(Type = Asn1Type.SEQUENCE_OF)]
            public List<UnencodedContainerWithSetOf> containers;
        }

        [Asn1Class(Type = Asn1Type.UNENCODED_CONTAINER)]
        public class UnencodedContainerWithSetOf
        {
            [Asn1Field(Type = Asn1Type.SET_OF)] public List<EmptySequence> values;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithBoolean
        {
            [Asn1Field(Type = Asn1Type.BOOLEAN)] public bool value;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithUTCTime
        {
            [Asn1Field(Type = Asn1Type.UTC_TIME)] public String value;
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithGeneralizedTime
        {
            [Asn1Field(Type = Asn1Type.GENERALIZED_TIME)]
            public String value;
        }
    }
}