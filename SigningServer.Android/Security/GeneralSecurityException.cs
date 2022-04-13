using System;

namespace SigningServer.Android.Security
{
    public class GeneralSecurityException : Exception
    {
        public GeneralSecurityException()
        {
        }

        public GeneralSecurityException(string message) : base(message)
        {
        }

        public GeneralSecurityException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}