using System.IO;

namespace SigningServer.Android.IO
{
    public class PrintStream
    {
        private readonly TextWriter mTextWriter;

        public PrintStream(TextWriter textWriter)
        {
            mTextWriter = textWriter;
        }
        
        public void Println(object o)
        {
            mTextWriter.WriteLine(o);
        }
    }
}