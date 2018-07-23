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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SigningServer.Android.Apk.Manifest
{
    /// <summary>
    /// Producer of <code>META-INF/MANIFEST.MF</code> file.
    /// <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#JAR_Manifest">JAR Manifest format</a>
    /// </summary>
    class ManifestWriter
    {
        private const int MaxLineLength = 70;

        public static void WriteMainSection(Stream output, Dictionary<string, string> attributes)
        {
            // Main section must start with the Manifest-Version attribute.
            // See https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File.
            if (!attributes.TryGetValue(Manifest.ManifestVersion, out var manifestVersion))
            {
                throw new ArgumentException("Mandatory " + Manifest.ManifestVersion + " attribute missing");
            }
            WriteAttribute(output, Manifest.ManifestVersion, manifestVersion);
            if (attributes.Count > 1)
            {
                var namedAttributes = GetAttributesSortedByName(attributes);
                namedAttributes.Remove(Manifest.ManifestVersion);
                WriteAttributes(output, namedAttributes);
            }
            WriteSectionDelimiter(output);
        }

        public static SortedDictionary<string, string> GetAttributesSortedByName(Dictionary<string, string> attributes)
        {
            var namedAttributes = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (var attribute in attributes)
            {
                var attrName = attribute.Key;
                var attrValue = attribute.Value;
                namedAttributes.Add(attrName, attrValue);
            }
            return namedAttributes;
        }

        public static void WriteSectionDelimiter(Stream output)
        {
            output.WriteByte((byte)'\r');
            output.WriteByte((byte)'\n');
        }

        public static void WriteAttributes(Stream output, SortedDictionary<string, string> attributes)
        {
            foreach (var attribute in attributes)
            {
                WriteAttribute(output, attribute.Key, attribute.Value);
            }

        }

        public static void WriteAttribute(Stream output, string name, object value)
        {
            WriteLine(output, name + ": " + value);
        }

        private static void WriteLine(Stream output, string line)
        {
            var lineBytes = Encoding.UTF8.GetBytes(line);
            var offset = 0;
            var remaining = lineBytes.Length;
            var firstLine = true;
            while (remaining > 0)
            {
                int chunkLength;
                if (firstLine)
                {
                    // First line
                    chunkLength = Math.Min(remaining, MaxLineLength);
                }
                else
                {
                    // Continuation line
                    output.WriteByte((byte)'\r');
                    output.WriteByte((byte)'\n');
                    output.WriteByte((byte)' ');
                    chunkLength = Math.Min(remaining, MaxLineLength - 1);
                }
                output.Write(lineBytes, offset, chunkLength);
                offset += chunkLength;
                remaining -= chunkLength;
                firstLine = false;
            }
            output.WriteByte((byte)'\r');
            output.WriteByte((byte)'\n');
        }

        public static void WriteIndividualSection(Stream output, string name, Dictionary<string, string> attributes)
        {
            WriteAttribute(output, "Name", name);
            if (attributes.Any())
            {
                WriteAttributes(output, GetAttributesSortedByName(attributes));
            }
            WriteSectionDelimiter(output);
        }
    }
}