/*
 * Copyright (C) 2016 The Android Open Source Project
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

namespace SigningServer.Android.ApkSig.Internal.Jar
{
    /**
     * Producer of {@code META-INF/MANIFEST.MF} file.
     *
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#JAR_Manifest">JAR Manifest format</a>
     */
    public abstract class ManifestWriter
    {
        private static readonly byte[] CRLF = new byte[] { (byte)'\r', (byte)'\n' };
        private static readonly int MAX_LINE_LENGTH = 70;

        private ManifestWriter()
        {
        }

        public static void writeMainSection(Stream @out, Attributes attributes)
        {
            // Main section must start with the Manifest-Version attribute.
            // See https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File.
            String manifestVersion = attributes.getValue(Attributes.Name.MANIFEST_VERSION.ToString());
            if (manifestVersion == null)
            {
                throw new ArgumentException(
                    "Mandatory " + Attributes.Name.MANIFEST_VERSION + " attribute missing");
            }

            writeAttribute(@out, Attributes.Name.MANIFEST_VERSION, manifestVersion);
            if (attributes.Count > 1)
            {
                SortedDictionary<String, String> namedAttributes = getAttributesSortedByName(attributes);
                namedAttributes.Remove(Attributes.Name.MANIFEST_VERSION.ToString());
                writeAttributes(@out, namedAttributes);
            }

            writeSectionDelimiter(@out);
        }

        public static void writeIndividualSection(Stream @out, String name, Attributes attributes)
        {
            writeAttribute(@out, "Name", name);
            if (attributes.Count != 0)
            {
                writeAttributes(@out, getAttributesSortedByName(attributes));
            }

            writeSectionDelimiter(@out);
        }

        public static void writeSectionDelimiter(Stream @out)
        {
            @out.Write(CRLF, 0, CRLF.Length);
        }

        public static void writeAttribute(Stream @out, Attributes.Name name, String value)
        {
            writeAttribute(@out, name.ToString(), value);
        }

        private static void writeAttribute(Stream @out, String name, String value)
        {
            writeLine(@out, name + ": " + value);
        }

        private static void writeLine(Stream @out, String line)
        {
            byte[] lineBytes = Encoding.UTF8.GetBytes(line);
            int offset = 0;
            int remaining = lineBytes.Length;

            bool firstLine = true;
            while (remaining > 0)
            {
                int chunkLength;
                if (firstLine)
                {
                    // First line
                    chunkLength = Math.Min(remaining, MAX_LINE_LENGTH);
                }
                else
                {
                    // Continuation line
                    @out.Write(CRLF, 0, CRLF.Length);
                    @out.WriteByte((byte)' ');
                    chunkLength = Math.Min(remaining, MAX_LINE_LENGTH - 1);
                }

                @out.Write(lineBytes, offset, chunkLength);
                offset += chunkLength;
                remaining -= chunkLength;
                firstLine = false;
            }

            @out.Write(CRLF, 0, CRLF.Length);
        }

        public static SortedDictionary<String, String> getAttributesSortedByName(Attributes attributes)
        {
            return new SortedDictionary<string, string>(attributes);
        }

        public static void writeAttributes(
            Stream @out, SortedDictionary<String, String> attributesSortedByName)

        {
            foreach (var attribute in attributesSortedByName)
            {
                String attrName = attribute.Key;
                String attrValue = attribute.Value;
                writeAttribute(@out, attrName, attrValue);
            }
        }
    }
}