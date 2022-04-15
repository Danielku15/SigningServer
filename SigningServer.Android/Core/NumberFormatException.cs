using System;

namespace SigningServer.Android.Core
{
    public class NumberFormatException : FormatException
    {
        public NumberFormatException()
        {
        }

        public NumberFormatException(string message) : base(message)
        {
        }

        public NumberFormatException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}