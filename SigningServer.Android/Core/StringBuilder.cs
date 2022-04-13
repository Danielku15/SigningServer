namespace SigningServer.Android.Core
{
    public class StringBuilder
    {
        private System.Text.StringBuilder _builder;

        public StringBuilder()
        {
            _builder = new System.Text.StringBuilder();
        }

        public StringBuilder(string initial)
        {
            _builder = new System.Text.StringBuilder();
            _builder.Append(initial);
        }

        public StringBuilder Append(object c)
        {
            _builder.Append(c);
            return this;
        }

        public int Length()
        {
            return _builder.Length;
        }
    }
}