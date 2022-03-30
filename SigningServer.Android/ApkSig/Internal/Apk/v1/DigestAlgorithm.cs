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
using System.ComponentModel;
using System.Reflection;

namespace SigningServer.Android.ApkSig.Internal.Apk.v1
{
    /**
     * Digest algorithm used with JAR signing (aka v1 signing scheme).
     */
    public enum DigestAlgorithm
    {
        /** SHA-1 */
        [Description("SHA-1")] SHA1,

        /** SHA2-256 */
        [Description("SHA-256")] SHA256
    }

    public static class DigestAlgorithmExtensions
    {
        public static string getJcaMessageDigestAlgorithm(this DigestAlgorithm digestAlgorithm)
        {
            return typeof(DigestAlgorithm)
                .GetField(digestAlgorithm.ToString())
                ?.GetCustomAttribute<DescriptionAttribute>()?.Description;
        }

        public static IComparer<DigestAlgorithm> BY_STRENGTH_COMPARATOR = new StrengthComparator();

        private class StrengthComparator : IComparer<DigestAlgorithm>
        {
            public int Compare(DigestAlgorithm a1, DigestAlgorithm a2)
            {
                switch (a1)
                {
                    case DigestAlgorithm.SHA1:
                        switch (a2)
                        {
                            case DigestAlgorithm.SHA1:
                                return 0;
                            case DigestAlgorithm.SHA256:
                                return -1;
                        }

                        throw new ArgumentException("Unsupported algorithm: " + a2);

                    case DigestAlgorithm.SHA256:
                        switch (a2)
                        {
                            case DigestAlgorithm.SHA1:
                                return 1;
                            case DigestAlgorithm.SHA256:
                                return 0;
                        }

                        throw new ArgumentException("Unsupported algorithm: " + a2);

                    default:
                        throw new ArgumentException("Unsupported algorithm: " + a1);
                }
            }
        }
    }
}