using System;
using System.Runtime.Serialization;

namespace SigningServer.ClientCore;

public class SigningFailedException : Exception
{
    public SigningFailedException()
    {
    }

    public SigningFailedException(string message) : base(message)
    {
    }

    public SigningFailedException(string message, Exception inner) : base(message, inner)
    {
    }
}
