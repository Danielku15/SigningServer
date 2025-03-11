using System;

namespace SigningServer.Android.IO
{
    internal class UnsupportedEncodingException : Exception
    {
        public UnsupportedEncodingException()
        {
        }

        public UnsupportedEncodingException(string message) : base(message)
        {
        }

        public UnsupportedEncodingException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}