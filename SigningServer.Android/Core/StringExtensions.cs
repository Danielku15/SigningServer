using System;
using System.Runtime.CompilerServices;
using System.Text;
using SigningServer.Android.IO;

namespace SigningServer.Android.Core
{
    public class StringExtensions
    {
        public static string Format(string format, params object[] args)
        {
            return format;
        }

        public static string Create(sbyte[] buffer, int offset, int length, Encoding encoding)
        {
            // CLR allows conversion from sbyte to byte array
            var unsigned = (byte[])(object)buffer;
            return encoding.GetString(unsigned, offset, length);
        }
        
        public static string Create(sbyte[] buffer, int offset, int length, string encoding)
        {
            Encoding encodingInstance;
            try
            {
                encodingInstance = Encoding.GetEncoding(encoding);
            }
            catch (ArgumentException e)
            {
                throw new UnsupportedEncodingException(e.Message);
            }
            
            // CLR allows conversion from sbyte to byte array
            var unsigned = (byte[])(object)buffer;
            return encodingInstance.GetString(unsigned, offset, length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ValueOf(int id)
        {
            return id.ToString();
        }

        public static string Create(sbyte[] patternBlob, string offset)
        {
            throw new NotImplementedException();
        }
    }
}