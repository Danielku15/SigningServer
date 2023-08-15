using System;
using System.Runtime.Serialization;

namespace SigningServer.ClientCore;

public class UnsupportedFileFormatException : Exception
{
    public UnsupportedFileFormatException()
    {
    }

    public UnsupportedFileFormatException(string message) : base(message)
    {
    }

    public UnsupportedFileFormatException(string message, Exception inner) : base(message, inner)
    {
    }
}
