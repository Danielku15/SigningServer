using System;

namespace SigningServer.Android.Util.Zip
{
    internal class DataFormatException : Exception
    {
        public DataFormatException()
        {
        }

        public DataFormatException(string message) : base(message)
        {
        }

        public DataFormatException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}