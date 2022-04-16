using System;
using System.IO;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SigningServer.Android
{
    [TestClass]
    public class TestBase
    {
        protected static DirectoryInfo CreateTemporaryFolder()
        {
            var info = new DirectoryInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
            if (!info.Exists)
            {
                info.Create();
            }
            return info;
        }


        protected static FileInfo CreateTemporaryFile(string name, string extension)
        {
            return new FileInfo(Path.Combine(Path.GetTempPath(), name + Guid.NewGuid().ToString("N") + extension));
        }

        protected static void AssumeNoException(Exception e)
        {
            // Nothing to do
        }
        
        protected static void AssertArrayEquals<T>(T[] expected, T[] actual)
        {
            actual.Should().Equal(expected);
        }
        
        protected static Exception AssertThrows(Type exceptionType, Action action)
        {
            try
            {
                action();
                Fail($"Expected exception of type {exceptionType.FullName}");
                return null;
            }
            catch (Exception e) when (exceptionType.IsInstanceOfType(e))
            {
                // Expected
                return e;
            }
        }

        protected static void AssertArrayEquals<T>(string message, T[] expected, T[] actual)
        {
            actual.Should().Equal(expected, message);
        }

        protected static void AssertSame<T>(T a, T b)
        {
            a.Should().BeSameAs(b);
        }

        protected static void AssertEquals<T>(string message, T expected, T actual)
        {
            actual.Should().Be(expected, message);
        }

        protected static void AssertNotEquals<T>(string message, T expected, T actual)
        {
            actual.Should().NotBe(expected, message);
        }

        protected static void AssertEquals<T>(T expected, T actual)
        {
            actual.Should().Be(expected);
        }

        protected static void AssertTrue(string message, bool value)
        {
            value.Should().BeTrue(message);
        }

        protected static void AssertTrue(bool value)
        {
            value.Should().BeTrue();
        }

        protected static void AssertNull(object o)
        {
            o.Should().BeNull();
        }

        protected static void AssertNotNull(object o)
        {
            o.Should().NotBeNull();
        }

        protected static void AssertFalse(string message, bool value)
        {
            value.Should().BeFalse(message);
        }

        protected static void AssertFalse(bool value)
        {
            value.Should().BeFalse();
        }

        protected static void Fail(string message)
        {
            Assert.Fail(message);
        }

        protected static void Fail()
        {
            Assert.Fail();
        }
    }
}