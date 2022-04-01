/*
 * Copyright (C) 2020 The Android Open Source Project
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

namespace SigningServer.Android.ApkSig.Internal.Apk
{
    /**
 * Base implementation of an APK signer.
 */
    public class ApkSignerInfo
    {
        public int index;
        public List<X509Certificate> certs = new List<X509Certificate>();
        public List<X509Certificate> certificateLineage = new List<X509Certificate>();

        private readonly List<ApkVerificationIssue> mWarnings = new List<ApkVerificationIssue>();
        private readonly List<ApkVerificationIssue> mErrors = new List<ApkVerificationIssue>();

        /**
         * Adds a new {@link ApkVerificationIssue} as an error to this signer using the provided {@code
         * issueId} and {@code params}.
         */
        public void addError(int issueId, params Object[] args)
        {
            mErrors.Add(new ApkVerificationIssue(issueId, args));
        }

        /**
         * Adds a new {@link ApkVerificationIssue} as a warning to this signer using the provided {@code
         * issueId} and {@code params}.
         */
        public void addWarning(int issueId, params Object[] args)
        {
            mWarnings.Add(new ApkVerificationIssue(issueId, args));
        }

        /**
         * Returns {@code true} if any errors were encountered during verification for this signer.
         */
        public bool containsErrors()
        {
            return mErrors.Count != 0;
        }

        /**
         * Returns {@code true} if any warnings were encountered during verification for this signer.
         */
        public bool containsWarnings()
        {
            return mErrors.Count != 0;
        }

        /**
         * Returns the errors encountered during verification for this signer.
         */
        public List<ApkVerificationIssue> getErrors()
        {
            return mErrors;
        }

        /**
         * Returns the warnings encountered during verification for this signer.
         */
        public List<ApkVerificationIssue> getWarnings()
        {
            return mWarnings;
        }
    }
}