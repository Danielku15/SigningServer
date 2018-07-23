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

namespace SigningServer.Android.Apk.Manifest
{
    /// <summary>
    /// Producer of JAR signature file (<code>*.SF</code>).
    /// <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#JAR_Manifest">JAR Manifest format</a>
    /// </summary>
    class SignatureFileWriter
    {
        public static void WriteMainSection(Stream output, Dictionary<string, string> attributes)
        {
            // Main section must start with the Signature-Version attribute.
            // See https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File.
            if (!attributes.TryGetValue("Signature-Version", out var signatureVersion))
            {
                throw new ArgumentException(
                    "Mandatory " + "Signature-Version" + " attribute missing");
            }
            ManifestWriter.WriteAttribute(output, "Signature-Version", signatureVersion);
            if (attributes.Count > 1)
            {
                var namedAttributes = ManifestWriter.GetAttributesSortedByName(attributes);
                namedAttributes.Remove("Signature-Version");
                ManifestWriter.WriteAttributes(output, namedAttributes);
            }
            WriteSectionDelimiter(output);
        }

        public static void WriteIndividualSection(MemoryStream output, string name, Dictionary<string, string> attributes)
        {
            ManifestWriter.WriteIndividualSection(output, name, attributes);
        }

        public static void WriteSectionDelimiter(Stream output)
        {
            ManifestWriter.WriteSectionDelimiter(output);
        }
    }
}