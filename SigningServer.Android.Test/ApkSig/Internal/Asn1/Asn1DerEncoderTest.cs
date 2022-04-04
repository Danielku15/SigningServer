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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.Test.ApkSig.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig.Internal.Asn1
{
    [TestClass]
    public class Asn1DerEncoderTest
    {
        [TestMethod]
        public void testInteger()
        {
            assertEquals("3003020100", encodeToHex(new SequenceWithInteger(0)));
            assertEquals("300302010c", encodeToHex(new SequenceWithInteger(12)));
            assertEquals("300302017f", encodeToHex(new SequenceWithInteger(0x7f)));
            assertEquals("3004020200ff", encodeToHex(new SequenceWithInteger(0xff)));
            assertEquals("30030201ff", encodeToHex(new SequenceWithInteger(-1)));
            assertEquals("3003020180", encodeToHex(new SequenceWithInteger(-128)));
            assertEquals("3005020300ffee", encodeToHex(new SequenceWithInteger(0xffee)));
            assertEquals("300602047fffffff", encodeToHex(new SequenceWithInteger(int.MaxValue)));
            assertEquals("3006020480000000", encodeToHex(new SequenceWithInteger(int.MinValue)));
        }

        [TestMethod]
        public void testOctetString()
        {
            assertEquals(
                "30050403010203",
                encodeToHex(
                    new SequenceWithByteBufferOctetString(
                        ByteBuffer.wrap(new byte[] { 1, 2, 3 }))));
            assertEquals(
                "30030401ff",
                encodeToHex(
                    new SequenceWithByteBufferOctetString(
                        ByteBuffer.wrap(new byte[] { (byte)0xff }))));

            assertEquals(
                "30020400",
                encodeToHex(
                    new SequenceWithByteBufferOctetString(ByteBuffer.wrap(new byte[0]))));
        }

        [TestMethod]
        public void testBitString()
        {
            assertEquals(
                "30050303010203",
                encodeToHex(
                    new SequenceWithByteBufferBitString(
                        ByteBuffer.wrap(new byte[] { 1, 2, 3 }))));
            assertEquals(
                "30030301ff",
                encodeToHex(
                    new SequenceWithByteBufferBitString(
                        ByteBuffer.wrap(new byte[] { (byte)0xff }))));

            assertEquals(
                "30020300",
                encodeToHex(
                    new SequenceWithByteBufferBitString(ByteBuffer.wrap(new byte[0]))));
        }


        [TestMethod]
        public void testOid()
        {
            assertEquals("3003060100", encodeToHex(new SequenceWithOid("0.0")));
            assertEquals(
                "300b06092b0601040182371514",
                encodeToHex(new SequenceWithOid("1.3.6.1.4.1.311.21.20")));
            assertEquals(
                "300b06092a864886f70d010701",
                encodeToHex(new SequenceWithOid("1.2.840.113549.1.7.1")));
            assertEquals(
                "300b0609608648016503040201",
                encodeToHex(new SequenceWithOid("2.16.840.1.101.3.4.2.1")));
        }

        [TestMethod]
        public void testChoice()
        {
            assertEquals("0201ff", encodeToHex(Choice.of(-1)));
            assertEquals("80092b0601040182371514", encodeToHex(Choice.of("1.3.6.1.4.1.311.21.20")));
        }

        [TestMethod]
        [ExpectedException(typeof(Asn1EncodingException))]
        public void testChoiceWithNoFieldsSet()
        {
            // CHOICE is required to have exactly one field set
            encode(new Choice(null, null));
        }

        [TestMethod]
        [ExpectedException(typeof(Asn1EncodingException))]
        public void testChoiceWithMultipleFieldsSet()
        {
            // CHOICE is required to have exactly one field set
            encode(new Choice(123, "1.3.6.1.4.1.311.21.20"));
        }

        [TestMethod]
        public void testSetOf()
        {
            assertEquals("3009310702010a020200ff", encodeToHex(SetOfIntegers.of(0x0a, 0xff)));
            // Reordering the elements of the set should not make a difference to the resulting encoding
            assertEquals("3009310702010a020200ff", encodeToHex(SetOfIntegers.of(0xff, 0x0a)));

            assertEquals(
                "300e310c02010a020200ff0203112233",
                encodeToHex(SetOfIntegers.of(0xff, 0x0a, 0x112233)));
        }

        [TestMethod]
        public void testSequence()
        {
            assertEquals(
                "30080201000601000400",
                encodeToHex(new Sequence(BigInteger.Zero, "0.0", new byte[0])));
            // Optional OBJECT IDENTIFIER not set
            assertEquals(
                "30050201000400",
                encodeToHex(new Sequence(BigInteger.Zero, null, new byte[0])));
            // Required INTEGER not set
            try
            {
                assertEquals(
                    "30050201000400",
                    encodeToHex(new Sequence(null, "0.0", new byte[0])));
                fail();
            }
            catch (Asn1EncodingException expected)
            {
            }
        }

        [TestMethod]
        public void testAsn1Class()
        {
            assertEquals(
                "30053003060100",
                encodeToHex(new SequenceWithAsn1Class(new SequenceWithOid("0.0"))));
        }

        [TestMethod]
        public void testOpaque()
        {
            assertEquals(
                "3003060100",
                encodeToHex(new SequenceWithOpaque(
                    new Asn1OpaqueObject(new byte[] { 0x06, 0x01, 0x00 }))));
        }

        [TestMethod]
        public void testBoolean()
        {
            assertEquals("3003010100", encodeToHex(new SequenceWithBoolean(false)));
            String value = encodeToHex(new SequenceWithBoolean(true));
            // The encoding of a true value can be any non-zero value so verify the static portion of
            // the encoding of a sequeuence with a boolean, then verify the last byte is non-zero
            assertEquals("The encoding of a sequence with a boolean is not the expected length.", 10,
                value.Length);
            assertEquals(
                "The prefix of the encoding of a sequence with a boolean is not the expected "
                + "value.",
                "30030101", value.Substring(0, 8));
            assertNotEquals("The encoding of true should be non-zero.", "00", value.Substring(8));
        }

        [TestMethod]
        public void testUTCTime()
        {
            assertEquals("300d170b313231323231313232315a",
                encodeToHex(new SequenceWithUTCTime("1212211221Z")));
            assertEquals("300d170b393931323331323335395a",
                encodeToHex(new SequenceWithUTCTime("9912312359Z")));
        }

        [TestMethod]
        public void testGeneralizedTime()
        {
            assertEquals("301518133230313231323231313232302e3939392d3037",
                encodeToHex(new SequenceWithGeneralizedTime("201212211220.999-07")));
            assertEquals("3017181532303338303131393033313430372e3030302b3030",
                encodeToHex(new SequenceWithGeneralizedTime("20380119031407.000+00")));
        }

        [TestMethod]
        public void testUnencodedContainer()
        {
            assertEquals("30233021310b30030201003004020200ff310830060204800000003108300602047fffffff",
                encodeToHex(
                    new SequenceWithSequenceOfUnencodedContainers(
                        new List<UnencodedContainerWithSetOfIntegers>
                        {
                            new UnencodedContainerWithSetOfIntegers(
                                new List<SequenceWithInteger>
                                {
                                    new SequenceWithInteger(0),
                                    new SequenceWithInteger(255)
                                }),
                            new UnencodedContainerWithSetOfIntegers(
                                new List<SequenceWithInteger>
                                {
                                    new SequenceWithInteger(
                                        int.MinValue)
                                }),
                            new UnencodedContainerWithSetOfIntegers(
                                new List<SequenceWithInteger>
                                {
                                    new SequenceWithInteger(int.MaxValue)
                                }
                            )
                        })
                )
            );
        }

        private static byte[] encode(Object obj)
        {
            return Asn1DerEncoder.encode(obj);
        }

        private static String encodeToHex(Object obj)
        {
            return TestHelpers.encodeHex(encode(obj));
        }


        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithInteger
        {
            [Asn1Field(Index = 1, Type = Asn1Type.INTEGER)]
            public int num;

            public SequenceWithInteger(int num)
            {
                this.num = num;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithOid
        {
            [Asn1Field(Index = 1, Type = Asn1Type.OBJECT_IDENTIFIER)]
            public String oid;

            public SequenceWithOid(String oid)
            {
                this.oid = oid;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithByteBufferOctetString
        {
            [Asn1Field(Index = 1, Type = Asn1Type.OCTET_STRING)]
            public ByteBuffer data;

            public SequenceWithByteBufferOctetString(ByteBuffer data)
            {
                this.data = data;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithByteBufferBitString
        {
            [Asn1Field(Index = 1, Type = Asn1Type.BIT_STRING)]
            public ByteBuffer data;

            public SequenceWithByteBufferBitString(ByteBuffer data)
            {
                this.data = data;
            }
        }

        [Asn1Class(Type = Asn1Type.CHOICE)]
        public class Choice
        {
            [Asn1Field(Type = Asn1Type.INTEGER)] public int? num;

            [Asn1Field(Type = Asn1Type.OBJECT_IDENTIFIER, Tagging = Asn1Tagging.IMPLICIT, TagNumber = 0)]
            public String oid;

            public Choice(int? num, String oid)
            {
                this.num = num;
                this.oid = oid;
            }

            public static Choice of(int num)
            {
                return new Choice(num, null);
            }

            public static Choice of(String oid)
            {
                return new Choice(null, oid);
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SetOfIntegers
        {
            [Asn1Field(Type = Asn1Type.SET_OF, ElementType = Asn1Type.INTEGER)]
            public List<int> values;

            public static SetOfIntegers of(params int[] values)
            {
                SetOfIntegers result = new SetOfIntegers();
                result.values = values.ToList();
                return result;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class Sequence
        {
            [Asn1Field(Type = Asn1Type.INTEGER, Index = 0)]
            public BigInteger? num;

            [Asn1Field(Type = Asn1Type.OBJECT_IDENTIFIER, Index = 1, Optional = true)]
            public String oid;

            [Asn1Field(Type = Asn1Type.OCTET_STRING, Index = 2)]
            public byte[] octets;

            public Sequence(BigInteger? num, String oid, byte[] octets)
            {
                this.num = num;
                this.oid = oid;
                this.octets = octets;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithAsn1Class
        {
            [Asn1Field(Type = Asn1Type.SEQUENCE)] public SequenceWithOid seqWithOid;

            public SequenceWithAsn1Class(SequenceWithOid seqWithOid)
            {
                this.seqWithOid = seqWithOid;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithOpaque
        {
            [Asn1Field(Type = Asn1Type.ANY)] public Asn1OpaqueObject obj;

            public SequenceWithOpaque(Asn1OpaqueObject obj)
            {
                this.obj = obj;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithBoolean
        {
            [Asn1Field(Index = 1, Type = Asn1Type.BOOLEAN)]
            public bool value;

            public SequenceWithBoolean(bool value)
            {
                this.value = value;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithUTCTime
        {
            [Asn1Field(Index = 1, Type = Asn1Type.UTC_TIME)]
            public String utcTime;

            public SequenceWithUTCTime(String utcTime)
            {
                this.utcTime = utcTime;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithGeneralizedTime
        {
            [Asn1Field(Index = 1, Type = Asn1Type.GENERALIZED_TIME)]
            public String generalizedTime;

            public SequenceWithGeneralizedTime(String generalizedTime)
            {
                this.generalizedTime = generalizedTime;
            }
        }

        [Asn1Class(Type = Asn1Type.SEQUENCE)]
        public class SequenceWithSequenceOfUnencodedContainers
        {
            [Asn1Field(Index = 1, Type = Asn1Type.SEQUENCE_OF)]
            public List<UnencodedContainerWithSetOfIntegers> containers;

            public SequenceWithSequenceOfUnencodedContainers(
                List<UnencodedContainerWithSetOfIntegers> containers)
            {
                this.containers = containers;
            }
        }

        [Asn1Class(Type = Asn1Type.UNENCODED_CONTAINER)]
        public class UnencodedContainerWithSetOfIntegers
        {
            [Asn1Field(Index = 1, Type = Asn1Type.SET_OF)]
            public List<SequenceWithInteger> values;

            public UnencodedContainerWithSetOfIntegers(List<SequenceWithInteger> values)
            {
                this.values = values;
            }
        }
    }
}