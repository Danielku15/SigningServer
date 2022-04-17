using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using SigningServer.Android.IO;

namespace SigningServer.Android.Core
{
    internal static class StringExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string Format(CultureInfo cultureInfo, string format, params object[] args)
        {
            return string.Format(cultureInfo, ConvertFormat(format), args);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string Format(string format, params object[] args)
        {
            return string.Format(ConvertFormat(format), args);
        }

        private static readonly Regex FormatSpecifier
            = new Regex("%(\\d+\\$)?([-#+ 0,(\\<]*)?(\\d+)?(\\.\\d+)?([tT])?([a-zA-Z%])", RegexOptions.Compiled);

        private static string ConvertFormat(string format)
        {
            var sb = new StringBuilder();

            var autoIndex = 0;
            for (var i = 0; i < format.Length;)
            {
                var m = FormatSpecifier.Match(format, i);
                if (m.Success)
                {
                    if (m.Index != i)
                    {
                        sb.Append(format, i, m.Index);
                    }
                    sb.Append("{");

                    if (m.Groups[1].Success)
                    {
                        var index = int.Parse(format.Substring(m.Groups[1].Index, m.Groups[1].Length - 1));
                        sb.Append(index - 1);
                    }
                    else
                    {
                        sb.Append(autoIndex);
                        autoIndex++;
                    }

                    // var padZero = false;
                    // var padSpace = false;
                    // if (m.Groups[2].Success)
                    // {
                    //     // flags
                    //     for (int flagIndex = 0; flagIndex < m.Groups[2].Length; flagIndex++)
                    //     {
                    //         var flag = format[m.Groups[2].Index + flagIndex];
                    //         switch (flag)
                    //         {
                    //             case '0':
                    //                 padZero = true;
                    //                 break;
                    //             case ' ':
                    //                 padSpace = true;
                    //                 break;
                    //         }
                    //     }
                    // }

                    int? width = null;
                    if (m.Groups[3].Success)
                    {
                        // width
                        if (int.TryParse(m.Groups[3].Value, out var v))
                        {
                            width = v;
                        }
                    }

                    int? precision = null;
                    if (m.Groups[4].Success)
                    {
                        // precision
                        if (int.TryParse(format.Substring(m.Groups[3].Index + 1, m.Groups[3].Length - 1), out var v))
                        {
                            precision = v;
                        }
                    }

                    if (m.Groups[5].Success)
                    {
                        // date/time conversion
                        throw new FormatException("Date/Time conversions not supported");
                    }


                    if (m.Groups[6].Success)
                    {
                        // conversion
                        switch (m.Groups[5].Value)
                        {
                            case "x":
                                sb.Append(":x");
                                if (width.HasValue)
                                {
                                    sb.Append(width.Value);
                                }
                                break;
                            case "X":
                                sb.Append(":X");
                                if (precision.HasValue)
                                {
                                    sb.Append(width.Value);
                                }
                                break;
                            // others ignored
                        }
                    }

                    sb.Append("}");

                    i = m.Index + m.Length;
                }
                else
                {
                    sb.Append(format, i, format.Length);
                    break;
                }
            }

            return sb.ToString();
        }

        public static string Create(byte[] buffer, int offset, int length, Encoding encoding)
        {
            return encoding.GetString(buffer, offset, length);
        }

        public static string Create(byte[] buffer, int offset, int length, string encoding)
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

            return encodingInstance.GetString(buffer, offset, length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string Create(byte[] data, Encoding encoding)
        {
            return encoding.GetString(data);
        }

        public static string Create(byte[] data, string encodingName)
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
        public static string Create(byte[] data)
        {
            return Encoding.Default.GetString(data);
        }
    }
}
