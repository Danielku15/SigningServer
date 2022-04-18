using System;
using System.Runtime.Serialization;

namespace SigningServer.Client;

[Serializable]
public class FileAlreadySignedException : Exception
{
    //
    // For guidelines regarding the creation of new exception types, see
    //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconerrorraisinghandlingguidelines.asp
    // and
    //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncscol/html/csharp07192001.asp
    //

    public FileAlreadySignedException()
    {
    }

    public FileAlreadySignedException(string message) : base(message)
    {
    }

    public FileAlreadySignedException(string message, Exception inner) : base(message, inner)
    {
    }

    protected FileAlreadySignedException(
        SerializationInfo info,
        StreamingContext context) : base(info, context)
    {
    }
}