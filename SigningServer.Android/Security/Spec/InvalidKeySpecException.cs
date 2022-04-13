using System;

namespace SigningServer.Android.Security.Spec
{
    public class InvalidKeySpecException : GeneralSecurityException
    {
        public InvalidKeySpecException()
        {
        }

        public InvalidKeySpecException(string message) : base(message)
        {
        }

        public InvalidKeySpecException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}