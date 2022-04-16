using System;

namespace SigningServer.Android.IO
{
    internal class BufferOverflowException : System.IO.IOException
    {
        public BufferOverflowException()
        {
        }

        public BufferOverflowException(string message) : base(message)
        {
        }

        public BufferOverflowException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}