using System;
using System.Runtime.Serialization;

namespace SigningServer.Client
{
    [Serializable]
    public class SigningFailedException : Exception
    {
        //
        // For guidelines regarding the creation of new exception types, see
        //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconerrorraisinghandlingguidelines.asp
        // and
        //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncscol/html/csharp07192001.asp
        //

        public SigningFailedException()
        {
        }

        public SigningFailedException(string message) : base(message)
        {
        }

        public SigningFailedException(string message, Exception inner) : base(message, inner)
        {
        }

        protected SigningFailedException(
            SerializationInfo info,
            StreamingContext context) : base(info, context)
        {
        }
    }
}