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
using System.Security.Cryptography;

namespace SigningServer.Android.Crypto
{
    public class DigestAlgorithm
    {
        public static readonly DigestAlgorithm SHA1 = new DigestAlgorithm("SHA-1", new Oid("1.3.14.3.2.26"), () => new SHA1CryptoServiceProvider());
        public static readonly DigestAlgorithm SHA256 = new DigestAlgorithm("SHA-256", new Oid("2.16.840.1.101.3.4.2.1"), () => new SHA256CryptoServiceProvider());
        public static readonly DigestAlgorithm SHA512 = new DigestAlgorithm("SHA-512", new Oid("2.16.840.1.101.3.4.2.3"),  () => new SHA512CryptoServiceProvider());

        private readonly Func<HashAlgorithm> _factory;

        public string Name { get; }
        public string DigestManifestAttributeName => Name + "-Digest-Manifest";
        public Oid Oid { get; set; }

        public DigestAlgorithm(string name, Oid oid, Func<HashAlgorithm> factory)
        {
            _factory = factory;
            Name = name;
            Oid = oid;
        }

        public HashAlgorithm CreateInstance()
        {
            return _factory();
        }

        protected bool Equals(DigestAlgorithm other)
        {
            return string.Equals(Name, other.Name);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((DigestAlgorithm)obj);
        }

        public override int GetHashCode()
        {
            return (Name != null ? Name.GetHashCode() : 0);
        }
    }
}