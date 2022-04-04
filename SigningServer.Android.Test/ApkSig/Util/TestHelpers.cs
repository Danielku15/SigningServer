using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SigningServer.Android.Test.ApkSig.Util
{
    public static class TestHelpers
    {
        public static void assertEquals<T>(string message, T a, T b)
        {
            a.Should().Be(b, message);
        }

        public static void assertNotEquals<T>(string message, T a, T b)
        {
            a.Should().NotBe(b, message);
        }

        public static void assertEquals<T>(T a, T b)
        {
            a.Should().Be(b);
        }

        public static void assertEquals<T>(IEnumerable<T> a, IEnumerable<T> b)
        {
            a.Should().Equal(b);
        }

        public static void assertSame<T>(T a, T b)
        {
            a.Should().BeSameAs(b);
        }

        public static void assertNull<T>(T a)
        {
            a.Should().BeNull();
        }

        public static void assertFalse(bool a)
        {
            a.Should().BeFalse();
        }

        public static void assertFalse(string message, bool a)
        {
            a.Should().BeFalse(message);
        }

        public static void assertTrue(bool a)
        {
            a.Should().BeTrue();
        }

        public static void assertTrue(string message, bool a)
        {
            a.Should().BeTrue(message);
        }

        public static void assertNotEquals<T>(T a, T b)
        {
            a.Should().NotBe(b);
        }

        public static void assertArrayEquals<T>(T[] a, T[] b)
        {
            a.Should().Equal(b);
        }

        public static void fail()
        {
            Assert.Fail();
        }

        public static void fail(string message)
        {
            Assert.Fail(message);
        }

        public static void assertNotNull<T>(T x)
        {
            x.Should().NotBeNull();
        }


        public static void assertByteBufferEquals(ByteBuffer buffer, ByteBuffer buffer2)
        {
            Assert.IsTrue(buffer.compareTo(buffer2) == 0,
                buffer + " vs " + buffer2 + ", byte array: " +
                TestHelpers.encodeHex(buffer.array()) + " vs " + encodeHex(buffer2.array()));
        }

        public static byte[] decodeHex(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static string encodeHex(byte[] raw)
        {
            return string.Join("", raw.Select(c => c.ToString("x2")));
        }

        public static string encodeHex(ByteBuffer raw)
        {
            var b = new byte[raw.remaining()];
            raw.get(b);
            return TestHelpers.encodeHex(b);
        }

        public static T assertThrows<T>(Action action) where T : Exception
        {
            try
            {
                action();
                fail("Expected exception " + typeof(T).FullName);
                return null;
            }
            catch (T exception)
            {
                // Expected
                return exception;
            }
        }
    }
}