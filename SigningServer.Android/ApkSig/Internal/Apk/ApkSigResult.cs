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
     * Base implementation of an APK signature verification result.
     */
    public class ApkSigResult
    {
        public readonly int signatureSchemeVersion;

        /** Whether the APK's Signature Scheme signature verifies. */
        public bool verified;

        public readonly List<ApkSignerInfo> mSigners = new List<ApkSignerInfo>();
        private readonly List<ApkVerificationIssue> mWarnings = new List<ApkVerificationIssue>();
        private readonly List<ApkVerificationIssue> mErrors = new List<ApkVerificationIssue>();

        public ApkSigResult(int signatureSchemeVersion)
        {
            this.signatureSchemeVersion = signatureSchemeVersion;
        }

        /**
         * Returns {@code true} if this result encountered errors during verification.
         */
        public virtual bool containsErrors()
        {
            if (mErrors.Count != 0)
            {
                return true;
            }

            if (mSigners.Count != 0)
            {
                foreach (ApkSignerInfo signer in mSigners)
                {
                    if (signer.containsErrors())
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /**
         * Returns {@code true} if this result encountered warnings during verification.
         */
        public virtual bool containsWarnings()
        {
            if (mWarnings.Count != 0)
            {
                return true;
            }

            if (mSigners.Count != 0)
            {
                foreach (ApkSignerInfo signer in mSigners)
                {
                    if (signer.containsWarnings())
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /**
         * Adds a new {@link ApkVerificationIssue} as an error to this result using the provided {@code
         * issueId} and {@code params}.
         */
        public virtual void addError(int issueId, params Object[] parameters)
        {
            mErrors.Add(new ApkVerificationIssue(issueId, parameters));
        }

        /**
         * Adds a new {@link ApkVerificationIssue} as a warning to this result using the provided {@code
         * issueId} and {@code params}.
         */
        public virtual void AddWarning(int issueId, params Object[] parameters)
        {
            mWarnings.Add(new ApkVerificationIssue(issueId, parameters));
        }

        /**
         * Returns the errors encountered during verification.
         */
        public virtual List<ApkVerificationIssue> getErrors()
        {
            return mErrors;
        }

        /**
         * Returns the warnings encountered during verification.
         */
        public virtual List<ApkVerificationIssue> getWarnings()
        {
            return mWarnings;
        }
    }
}