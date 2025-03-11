using System.Collections.Generic;

namespace SigningServer.Android.Util
{
    internal class StringTokenizer
    {
        private readonly Queue<string> _tokens;

        public StringTokenizer(string s, string separators = " \t\n\r\f")
        {
            _tokens = new Queue<string>(s.Split(separators.ToCharArray()));
        }

        public bool HasMoreTokens()
        {
            return _tokens.Count > 0;
        }

        public string NextToken()
        {
            return _tokens.Dequeue();
        }
    }
}
