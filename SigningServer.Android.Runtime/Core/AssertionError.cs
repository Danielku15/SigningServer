using System;

namespace SigningServer.Android.Core
{
    internal class AssertionError : Exception
    {
        public AssertionError()
        {
        }

        public AssertionError(string message) : base(message)
        {
        }

        public AssertionError(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}