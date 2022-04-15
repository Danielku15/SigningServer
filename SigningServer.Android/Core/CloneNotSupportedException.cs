using System;

namespace SigningServer.Android.Core
{
    public class CloneNotSupportedException : Exception
    {
        public CloneNotSupportedException()
        {
        }

        public CloneNotSupportedException(string message) : base(message)
        {
        }

        public CloneNotSupportedException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}