using System;
using System.Runtime.Serialization;

namespace SigningServer.ClientCore;

public class FileAlreadySignedException : Exception
{
    public FileAlreadySignedException()
    {
    }

    public FileAlreadySignedException(string message) : base(message)
    {
    }

    public FileAlreadySignedException(string message, Exception inner) : base(message, inner)
    {
    }
}
