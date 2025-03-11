
namespace SigningServer.Android.Core
{
    internal class StringBuilder
    {
        private readonly global::System.Text.StringBuilder _builder;

        public StringBuilder()
        {
            _builder = new global::System.Text.StringBuilder();
        }

        public StringBuilder(string initial)
        {
            _builder = new global::System.Text.StringBuilder(initial);
        }

        public StringBuilder(int capacity)
        {
            _builder = new global::System.Text.StringBuilder(capacity);
        }

        public StringBuilder Append(long v)
        {
            _builder.Append(v);
            return this;
        }

        public StringBuilder Append(char c)
        {
            _builder.Append(c);
            return this;
        }
        
        public StringBuilder Append(int v)
        {
            _builder.Append(v);
            return this;
        }

        public StringBuilder Append(byte v)
        {
            _builder.Append(v);
            return this;
        }

        public StringBuilder Append(string s)
        {
            _builder.Append(s);
            return this;
        }

        public void Append(string s, int start, int end)
        {
            _builder.Append(s, start, end - start);
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

        public override string ToString()
        {
            return _builder.ToString();
        }
    }
}
