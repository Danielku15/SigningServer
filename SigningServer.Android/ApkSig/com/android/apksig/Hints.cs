// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig
{
    public class Hints
    {
        /// <summary>
        /// Name of hint pattern asset file in APK.
        /// </summary>
        public static readonly string PIN_HINT_ASSET_ZIP_ENTRY_NAME = "assets/com.android.hints.pins.txt";
        
        /// <summary>
        /// Name of hint byte range data file in APK.  Keep in sync with PinnerService.java.
        /// </summary>
        public static readonly string PIN_BYTE_RANGE_ZIP_ENTRY_NAME = "pinlist.meta";
        
        internal static int ClampToInt(long value)
        {
            return (int)SigningServer.Android.Core.Math.Max(0, SigningServer.Android.Core.Math.Min(value, SigningServer.Android.Core.IntExtensions.MaxValue));
        }
        
        public class ByteRange
        {
            public readonly long start;
            
            public readonly long end;
            
            public ByteRange(long start, long end)
            {
                this.start = start;
                this.end = end;
            }
            
        }
        
        public class PatternWithRange
        {
            public readonly SigningServer.Android.Util.Regex.Pattern pattern;
            
            public readonly long offset;
            
            public readonly long size;
            
            public PatternWithRange(string pattern)
            {
                this.pattern = SigningServer.Android.Util.Regex.Pattern.Compile(pattern);
                this.offset = 0;
                this.size = SigningServer.Android.Core.LongExtensions.MAX_VALUE;
            }
            
            public PatternWithRange(string pattern, long offset, long size)
            {
                this.pattern = SigningServer.Android.Util.Regex.Pattern.Compile(pattern);
                this.offset = offset;
                this.size = size;
            }
            
            public virtual SigningServer.Android.Util.Regex.Matcher Matcher(string input)
            {
                return this.pattern.Matcher(input);
            }
            
            public virtual SigningServer.Android.Com.Android.Apksig.Hints.ByteRange ClampToAbsoluteByteRange(SigningServer.Android.Com.Android.Apksig.Hints.ByteRange rangeIn)
            {
                if (rangeIn.end - rangeIn.start < this.offset)
                {
                    return null;
                }
                long rangeOutStart = rangeIn.start + this.offset;
                long rangeOutSize = SigningServer.Android.Core.Math.Min(rangeIn.end - rangeOutStart, this.size);
                return new SigningServer.Android.Com.Android.Apksig.Hints.ByteRange(rangeOutStart, rangeOutStart + rangeOutSize);
            }
            
        }
        
        /// <summary>
        /// Create a blob of bytes that PinnerService understands as a
        /// sequence of byte ranges to pin.
        /// </summary>
        public static sbyte[] EncodeByteRangeList(SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Hints.ByteRange> pinByteRanges)
        {
            SigningServer.Android.IO.ByteArrayOutputStream bos = new SigningServer.Android.IO.ByteArrayOutputStream(pinByteRanges.Size() * 8);
            SigningServer.Android.IO.DataOutputStream output = new SigningServer.Android.IO.DataOutputStream(bos);
            try
            {
                foreach (SigningServer.Android.Com.Android.Apksig.Hints.ByteRange pinByteRange in pinByteRanges)
                {
                    output.WriteInt(SigningServer.Android.Com.Android.Apksig.Hints.ClampToInt(pinByteRange.start));
                    output.WriteInt(SigningServer.Android.Com.Android.Apksig.Hints.ClampToInt(pinByteRange.end - pinByteRange.start));
                }
            }
            catch (SigningServer.Android.IO.IOException ex)
            {
                throw new SigningServer.Android.Core.AssertionError("impossible", ex);
            }
            return bos.ToByteArray();
        }
        
        public static SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Hints.PatternWithRange> ParsePinPatterns(sbyte[] patternBlob)
        {
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Hints.PatternWithRange> pinPatterns = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Hints.PatternWithRange>();
            try
            {
                foreach (string rawLine in SigningServer.Android.Core.StringExtensions.Create(patternBlob, "UTF-8").Split("\n"))
                {
                    string line = rawLine.ReplaceFirst("#.*", "");
                    string[] fields = line.Split(" ");
                    if (fields.Length == 1)
                    {
                        pinPatterns.Add(new SigningServer.Android.Com.Android.Apksig.Hints.PatternWithRange(fields[0]));
                    }
                    else if (fields.Length == 3)
                    {
                        long start = SigningServer.Android.Core.LongExtensions.ParseLong(fields[1]);
                        long end = SigningServer.Android.Core.LongExtensions.ParseLong(fields[2]);
                        pinPatterns.Add(new SigningServer.Android.Com.Android.Apksig.Hints.PatternWithRange(fields[0], start, end - start));
                    }
                    else 
                    {
                        throw new SigningServer.Android.Core.AssertionError("bad pin pattern line " + line);
                    }
                }
            }
            catch (SigningServer.Android.IO.UnsupportedEncodingException ex)
            {
                throw new SigningServer.Android.Core.RuntimeException("UTF-8 must be supported", ex);
            }
            return pinPatterns;
        }
        
    }
    
}