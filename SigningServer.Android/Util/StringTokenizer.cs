using System;
using System.Collections.Generic;

namespace SigningServer.Android.Util
{
    public class StringTokenizer
    {
        private Queue<string> _tokens;

        public StringTokenizer(string s, string separator)
        {
            _tokens = new Queue<string>(s.Split(new[] { separator }, StringSplitOptions.None));
        }

        public StringTokenizer(string s)
        {
            _tokens = new Queue<string>(s.Split(new[] { separator }, StringSplitOptions.None));
        }


        public bool HasMoreTokens()
        {
            throw new NotImplementedException();
        }

        public string NextToken()
        {
            throw new NotImplementedException();
        }
    }
}