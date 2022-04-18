using System;
using System.Runtime.Serialization;

namespace SigningServer.Server.Configuration;

[Serializable]
public class InvalidConfigurationException : Exception
{
    public const string NoValidCertificatesMessage = "No valid certificates found";
    public const string CreateWorkingDirectoryFailedMessage = "Could not create working directory";
    //
    // For guidelines regarding the creation of new exception types, see
    //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconerrorraisinghandlingguidelines.asp
    // and
    //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncscol/html/csharp07192001.asp
    //

    public InvalidConfigurationException()
    {
    }

    public InvalidConfigurationException(string message) : base(message)
    {
    }

    public InvalidConfigurationException(string message, Exception inner) : base(message, inner)
    {
    }

    protected InvalidConfigurationException(
        SerializationInfo info,
        StreamingContext context) : base(info, context)
    {
    }
}