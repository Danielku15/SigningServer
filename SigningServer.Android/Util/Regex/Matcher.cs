namespace SigningServer.Android.Util.Regex
{
    public class Matcher
    {
        private readonly System.Text.RegularExpressions.Regex mRegex;
        private readonly string mInput;

        public Matcher(System.Text.RegularExpressions.Regex regex, string input)
        {
            mRegex = regex;
            mInput = input;
        }

        public bool Matches()
        {
            return mRegex.IsMatch(mInput);
        }
    }
}