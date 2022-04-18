
using System.Text.RegularExpressions;

namespace SigningServer.Android.Util.Regex
{
    public class Pattern
    {
        private readonly System.Text.RegularExpressions.Regex _regex;

        private Pattern(System.Text.RegularExpressions.Regex regex)
        {
            _regex = regex;
        }

        public static Pattern Compile(string pattern)
        {
            return new Pattern(new System.Text.RegularExpressions.Regex(pattern, RegexOptions.Compiled));
        }

        public Matcher Matcher(string input)
        {
            return new Matcher(_regex, input);
        }
    }
}
