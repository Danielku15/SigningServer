using System;

namespace SigningServer.Android.Security
{
    internal class KeyException : GeneralSecurityException
    {
        public KeyException()
        {
        }

        public KeyException(string message) : base(message)
        {
        }

        public KeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}