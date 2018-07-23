/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2018 Daniel Kuschny (C# port based on oreo-master)
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

using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SigningServer.Android.Apk.Manifest
{
    /// <summary>
    /// Reads a JAR file manifest. The specification is here:
    /// http://java.sun.com/javase/6/docs/technotes/guides/jar/jar.html
    /// </summary>
    /// <remarks>
    /// Based on https://android.googlesource.com/platform/libcore/+/marshmallow-release/luni/src/main/java/java/util/jar/ManifestReader.java (2018-07-23)
    /// </remarks>
    class ManifestReader
    {
        private readonly Dictionary<string, string> _attributeNameCache = new Dictionary<string, string>();
        private readonly byte[] _buf;
        private string _name;
        private string _value;
        private int _pos;
        private int _consecutiveLineBreaks = 0;
        private readonly MemoryStream _valueBuffer = new MemoryStream(80);

        public ManifestReader(byte[] buf, Dictionary<string, string> main)
        {
            _buf = buf;
            while (ReadHeader())
            {
                main.Add(_name, _value);
            }
        }

        private bool ReadHeader()
        {
            if (_consecutiveLineBreaks > 1)
            {
                // break a section on an empty line
                _consecutiveLineBreaks = 0;
                return false;
            }
            ReadName();
            _consecutiveLineBreaks = 0;
            ReadValue();
            // if the last line break is missed, the line
            // is ignored by the reference implementation
            return _consecutiveLineBreaks > 0;
        }

        private void ReadName()
        {
            var mark = _pos;
            while (_pos < _buf.Length)
            {
                if (_buf[_pos++] != ':')
                {
                    continue;
                }
                var nameString = Encoding.ASCII.GetString(_buf, mark, _pos - mark - 1);
                if (_buf[_pos++] != ' ')
                {
                    throw new IOException(string.Format("Invalid value for attribute '{0}'", nameString));
                }
                if (!_attributeNameCache.TryGetValue(nameString, out _name))
                {
                    _attributeNameCache[nameString] = _name = nameString;
                }

                return;
            }
        }

        private void ReadValue()
        {
            var lastCr = false;
            var mark = _pos;
            var last = _pos;
            _valueBuffer.SetLength(0);
            _valueBuffer.Position = 0;

            while (_pos < _buf.Length)
            {
                var next = (char)_buf[_pos++];
                switch (next)
                {
                    case '\0':
                        throw new IOException("NUL character in a manifest");
                    case '\n':
                        if (lastCr)
                        {
                            lastCr = false;
                        }
                        else
                        {
                            _consecutiveLineBreaks++;
                        }
                        continue;
                    case '\r':
                        lastCr = true;
                        _consecutiveLineBreaks++;
                        continue;
                    case ' ':
                        if (_consecutiveLineBreaks == 1)
                        {
                            _valueBuffer.Write(_buf, mark, last - mark);
                            mark = _pos;
                            _consecutiveLineBreaks = 0;
                            continue;
                        }

                        break;
                }
                if (_consecutiveLineBreaks >= 1)
                {
                    _pos--;
                    break;
                }
                last = _pos;
            }
            _valueBuffer.Write(_buf, mark, last - mark);
            // A bit frustrating that that Charset.forName will be called
            // again.
            _value = Encoding.UTF8.GetString(_valueBuffer.ToArray());
        }

        public void ReadEntries(Dictionary<string, Dictionary<string, string>> entries)
        {
            while (ReadHeader())
            {
                if (!Manifest.Name.Equals(_name))
                {
                    throw new IOException("Entry is not named");
                }
                var entryNameValue = _value;

                if (!entries.TryGetValue(entryNameValue, out var entry))
                {
                    entry = new Dictionary<string, string>();
                }

                while (ReadHeader())
                {
                    entry.Add(_name, _value);
                }
                entries.Add(entryNameValue, entry);
            }
        }
    }
}