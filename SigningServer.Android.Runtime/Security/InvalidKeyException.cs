using System;

namespace SigningServer.Android.Security
{
    internal class InvalidKeyException : KeyException
    {
        public InvalidKeyException()
        {
        }

        public InvalidKeyException(string message) : base(message)
        {
        }

        public InvalidKeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}