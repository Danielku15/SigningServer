/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace SigningServer.Android.ApkSig
{
    public sealed class Hints
    {
        /**
         * Name of hint pattern asset file in APK.
         */
        public static readonly string PIN_HINT_ASSET_ZIP_ENTRY_NAME = "assets/com.android.hints.pins.txt";

        /**
         * Name of hint byte range data file in APK.  Keep in sync with PinnerService.java.
         */
        public static readonly string PIN_BYTE_RANGE_ZIP_ENTRY_NAME = "pinlist.meta";

        private static int clampToInt(long value)
        {
            return (int)Math.Max(0, Math.Min(value, int.MaxValue));
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
            public readonly Regex pattern;
            public readonly long offset;
            public readonly long size;

            public PatternWithRange(string pattern)
            {
                this.pattern = new Regex(pattern, RegexOptions.Compiled);
                this.offset = 0;
                this.size = long.MaxValue;
            }

            public PatternWithRange(string pattern, long offset, long size)
            {
                this.pattern = new Regex(pattern, RegexOptions.Compiled);
                this.offset = offset;
                this.size = size;
            }

            public MatchCollection matcher(string input)
            {
                return this.pattern.Matches(input);
            }

            public ByteRange ClampToAbsoluteByteRange(ByteRange rangeIn)
            {
                if (rangeIn.end - rangeIn.start < this.offset)
                {
                    return null;
                }

                long rangeOutStart = rangeIn.start + this.offset;
                long rangeOutSize = Math.Min(rangeIn.end - rangeOutStart,
                    this.size);
                return new ByteRange(rangeOutStart,
                    rangeOutStart + rangeOutSize);
            }
        }

        /**
         * Create a blob of bytes that PinnerService understands as a
         * sequence of byte ranges to pin.
         */
        public static byte[] encodeByteRangeList(List<ByteRange> pinByteRanges)
        {
            var bos = new MemoryStream(pinByteRanges.Count * 8);
            var @out = new BinaryWriter(bos);
            foreach (var pinByteRange in pinByteRanges)
            {
                @out.Write(clampToInt(pinByteRange.start));
                @out.Write(clampToInt(pinByteRange.end - pinByteRange.start));
            }

            return bos.ToArray();
        }

        public static List<PatternWithRange> parsePinPatterns(byte[] patternBlob)
        {
            List<PatternWithRange> pinPatterns = new List<PatternWithRange>();
            foreach (string rawLine in Encoding.UTF8.GetString(patternBlob).Split('\n'))
            {
                string line = rawLine.ReplaceFirst("#.*", ""); // # starts a comment
                string[] fields = line.Split(' ');
                if (fields.Length == 1)
                {
                    pinPatterns.Add(new PatternWithRange(fields[0]));
                }
                else if (fields.Length == 3)
                {
                    long start = long.Parse(fields[1]);
                    long end = long.Parse(fields[2]);
                    pinPatterns.Add(new PatternWithRange(fields[0], start, end - start));
                }
                else
                {
                    throw new IOException("bad pin pattern line " + line);
                }
            }

            return pinPatterns;
        }
    }
}