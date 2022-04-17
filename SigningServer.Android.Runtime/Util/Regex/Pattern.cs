
using System.Text.RegularExpressions;

namespace SigningServer.Android.Util.Regex
{
    public class Pattern
    {
        private readonly System.Text.RegularExpressions.Regex mRegex;

        private Pattern(System.Text.RegularExpressions.Regex regex)
        {
            mRegex = regex;
        }

        public static Pattern Compile(string pattern)
        {
            return new Pattern(new System.Text.RegularExpressions.Regex(pattern, RegexOptions.Compiled));
        }

        public Matcher Matcher(string input)
        {
            return new Matcher(mRegex, input);
        }
    }
}