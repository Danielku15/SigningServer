using System;

namespace SigningServer.Android.Core
{
    public class RuntimeException : ApplicationException
    {
        public RuntimeException()
        {
        }

        public RuntimeException(Exception inner) : base(inner.Message, inner)
        {
        }
        public RuntimeException(string message) : base(message)
        {
        }

        public RuntimeException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}