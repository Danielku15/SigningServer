using System;

namespace SigningServer.Android.Security
{
    internal class SignatureException : Exception
    {
        public SignatureException(string message) : base(message)
        {
        }

        public SignatureException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}