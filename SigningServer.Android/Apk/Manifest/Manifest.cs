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

namespace SigningServer.Android.Apk.Manifest
{
    class Manifest
    {
        public const string ManifestVersion = "Manifest-Version";
        public const string SignatureVersion = "Signature-Version";
        public const string Name = "Name";

        public Dictionary<string, string> MainAttributes { get; }
        public Dictionary<string, Dictionary<string, string>> Entries { get; }

        public Manifest()
        {
            MainAttributes = new Dictionary<string, string>();
            Entries = new Dictionary<string, Dictionary<string, string>>();
        }

        public Manifest(byte[] data) : this()
        {
            Read(data);
        }

        private void Read(byte[] data)
        {
            var im = new ManifestReader(data, MainAttributes);
            im.ReadEntries(Entries);
        }

    }
}
