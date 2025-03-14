﻿using System;

namespace SigningServer.Android.IO
{
    internal class BufferUnderflowException : System.IO.IOException
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
}