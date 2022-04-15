using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using SigningServer.Android.IO;

namespace SigningServer.Android.Core
{
    public static class StringExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string Format(CultureInfo cultureInfo, string format, params object[] args)
        {
            // NOTE: not perfect, but enough for us
            return format + string.Join(", ", args);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string Format(string format, params object[] args)
        {
            // NOTE: not perfect, but enough for us
            return format + string.Join(", ", args);
        }

        public static string Create(sbyte[] buffer, int offset, int length, Encoding encoding)
        {
            return encoding.GetString(buffer.AsBytes(), offset, length);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string Create(sbyte[] data, Encoding encoding)
        {
            return encoding.GetString(data.AsBytes());
        }

        public static string Create(sbyte[] data, string encodingName)
        {
            Encoding encoding;
            try
            {
                encoding = Encoding.GetEncoding(encodingName);
            }
            catch (ArgumentException e)
            {
                throw new UnsupportedEncodingException(e.Message, e);
            }

            return Create(data, encoding);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string Create(sbyte[] data)
        {
            return Encoding.Default.GetString(data.AsBytes());
        }
    }
}