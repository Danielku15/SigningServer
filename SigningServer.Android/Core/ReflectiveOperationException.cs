using System;

namespace SigningServer.Android.Core
{
    public class ReflectiveOperationException :Exception
    {
        public ReflectiveOperationException()
        {
        }

        public ReflectiveOperationException(string message) : base(message)
        {
        }

        public ReflectiveOperationException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}