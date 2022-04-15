using NotImplementedException = System.NotImplementedException;

namespace SigningServer.Android.Core
{
    public class StringBuilder
    {
        private readonly global::System.Text.StringBuilder mBuilder;

        public StringBuilder()
        {
            mBuilder = new global::System.Text.StringBuilder();
        }

        public StringBuilder(string initial)
        {
            mBuilder = new global::System.Text.StringBuilder();
            mBuilder.Append(initial);
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

        public StringBuilder Append(int v)
        {
            mBuilder.Append(v);
            return this;
        }

        public StringBuilder Append(sbyte v)
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
    }
}