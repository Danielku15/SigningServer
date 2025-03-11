namespace SigningServer.Android.Util.Regex
{
    public class Matcher
    {
        private readonly System.Text.RegularExpressions.Regex _regex;
        private readonly string _input;

        public Matcher(System.Text.RegularExpressions.Regex regex, string input)
        {
            _regex = regex;
            _input = input;
        }

        public bool Matches()
        {
            return _regex.IsMatch(_input);
        }
    }
}
