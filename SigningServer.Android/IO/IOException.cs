using System;

namespace SigningServer.Android.IO
{
    public class IOException : System.IO.IOException
    {
        public IOException()
        {
        }

        public IOException(string message) : base(message)
        {
        }

        public IOException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}