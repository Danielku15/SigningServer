using System;

namespace SigningServer.Android.Security
{
    internal class NoSuchAlgorithmException : GeneralSecurityException
    {
        public NoSuchAlgorithmException()
        {
        }

        public NoSuchAlgorithmException(string message) : base(message)
        {
        }

        public NoSuchAlgorithmException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}