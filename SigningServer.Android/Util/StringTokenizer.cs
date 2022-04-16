using System.Collections.Generic;

namespace SigningServer.Android.Util
{
    public class StringTokenizer
    {
        private readonly Queue<string> mTokens;

        public StringTokenizer(string s, string separators = " \t\n\r\f")
        {
            mTokens = new Queue<string>(s.Split(separators.ToCharArray()));
        }

        public bool HasMoreTokens()
        {
            return mTokens.Count > 0;
        }

        public string NextToken()
        {
            return mTokens.Dequeue();
        }
    }
}