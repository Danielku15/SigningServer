using System;

namespace SigningServer.Android.IO
{
    public class BufferUnderflowException : System.IO.IOException
    {
        public BufferUnderflowException()
        {
        }

        public BufferUnderflowException(string message) : base(message)
        {
        }

        public BufferUnderflowException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    public class BufferOverflowException : System.IO.IOException
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