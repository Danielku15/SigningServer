
namespace SigningServer.Android.Core
{
    internal class StringBuilder
    {
        private readonly global::System.Text.StringBuilder mBuilder;

        public StringBuilder()
        {
            mBuilder = new global::System.Text.StringBuilder();
        }

        public StringBuilder(string initial)
        {
            mBuilder = new global::System.Text.StringBuilder(initial);
        }

        public StringBuilder(int capacity)
        {
            mBuilder = new global::System.Text.StringBuilder(capacity);
        }

        public StringBuilder Append(long v)
        {
            mBuilder.Append(v);
            return this;
        }

        public StringBuilder Append(char c)
        {
            mBuilder.Append(c);
            return this;
        }
        
        public StringBuilder Append(int v)
        {
            mBuilder.Append(v);
            return this;
        }

        public StringBuilder Append(byte v)
        {
            mBuilder.Append(v);
            return this;
        }

        public StringBuilder Append(string s)
        {
            mBuilder.Append(s);
            return this;
        }

        public StringBuilder Append(string s, int start, int end)
        {
            mBuilder.Append(s, start, end - start);
            return this;
        }

        public StringBuilder Append(object c)
        {
            mBuilder.Append(c);
            return this;
        }

        public int Length()
        {
            return mBuilder.Length;
        }

        public override string ToString()
        {
            return mBuilder.ToString();
        }
    }
}