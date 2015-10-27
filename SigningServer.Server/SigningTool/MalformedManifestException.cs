using System;
using System.Runtime.Serialization;

namespace SigningServer.Server.SigningTool
{
    [Serializable]
    public class MalformedManifestException : Exception
    {
        //
        // For guidelines regarding the creation of new exception types, see
        //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconerrorraisinghandlingguidelines.asp
        // and
        //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncscol/html/csharp07192001.asp
        //

        public MalformedManifestException()
        {
        }

        public MalformedManifestException(string message) : base(message)
        {
        }

        public MalformedManifestException(string message, Exception inner) : base(message, inner)
        {
        }

        protected MalformedManifestException(
            SerializationInfo info,
            StreamingContext context) : base(info, context)
        {
        }
    }
}