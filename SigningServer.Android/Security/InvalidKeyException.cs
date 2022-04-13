using System;

namespace SigningServer.Android.Security
{
    public class KeyException : GeneralSecurityException
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
        
    public class InvalidKeyException : KeyException
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