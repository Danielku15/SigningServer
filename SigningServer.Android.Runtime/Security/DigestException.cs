using System;

namespace SigningServer.Android.Security
{
    internal class DigestException : GeneralSecurityException
    {
        public DigestException()
        {
        }

        public DigestException(string message) : base(message)
        {
        }

        public DigestException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}