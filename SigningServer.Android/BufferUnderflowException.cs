using System;
using System.IO;

namespace SigningServer.Android
{
    public class BufferUnderflowException : IOException
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

    public class BufferOverflowException : IOException
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