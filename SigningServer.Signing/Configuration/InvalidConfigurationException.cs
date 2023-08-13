using System;

namespace SigningServer.Signing.Configuration;

public class InvalidConfigurationException : Exception
{
    public const string NoValidCertificatesMessage = "No valid certificates found";
    public const string CreateWorkingDirectoryFailedMessage = "Could not create working directory";

    public InvalidConfigurationException()
    {
    }

    public InvalidConfigurationException(string message) : base(message)
    {
    }

    public InvalidConfigurationException(string message, Exception inner) : base(message, inner)
    {
    }
}
