// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

/*
 * Copyright (C) 2022 Daniel Kuschny (C# port)
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

namespace SigningServer.Android.Com.Android.Apksig.Internal.Apk
{
    /// <summary>
    /// Base implementation of an APK signature verification result.
    /// </summary>
    public class ApkSigResult
    {
        public readonly int signatureSchemeVersion;
        
        /// <summary>
        /// Whether the APK's Signature Scheme signature verifies.
        /// </summary>
        public bool verified;
        
        public readonly SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSignerInfo> mSigners = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSignerInfo>();
        
        internal readonly SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.ApkVerificationIssue> mWarnings = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.ApkVerificationIssue>();
        
        internal readonly SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.ApkVerificationIssue> mErrors = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.ApkVerificationIssue>();
        
        public ApkSigResult(int signatureSchemeVersion)
        {
            this.signatureSchemeVersion = signatureSchemeVersion;
        }
        
        /// <summary>
        /// Returns {@code true} if this result encountered errors during verification.
        /// </summary>
        public virtual bool ContainsErrors()
        {
            if (!mErrors.IsEmpty())
            {
                return true;
            }
            if (!mSigners.IsEmpty())
            {
                foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSignerInfo signer in mSigners)
                {
                    if (signer.ContainsErrors())
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        
        /// <summary>
        /// Returns {@code true} if this result encountered warnings during verification.
        /// </summary>
        public virtual bool ContainsWarnings()
        {
            if (!mWarnings.IsEmpty())
            {
                return true;
            }
            if (!mSigners.IsEmpty())
            {
                foreach (SigningServer.Android.Com.Android.Apksig.Internal.Apk.ApkSignerInfo signer in mSigners)
                {
                    if (signer.ContainsWarnings())
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        
        /// <summary>
        /// Adds a new {@link ApkVerificationIssue} as an error to this result using the provided {@code
        /// issueId} and {@code params}.
        /// </summary>
        public virtual void AddError(int issueId, params object[] parameters)
        {
            mErrors.Add(new SigningServer.Android.Com.Android.Apksig.ApkVerificationIssue(issueId, parameters));
        }
        
        /// <summary>
        /// Adds a new {@link ApkVerificationIssue} as a warning to this result using the provided {@code
        /// issueId} and {@code params}.
        /// </summary>
        public virtual void AddWarning(int issueId, params object[] parameters)
        {
            mWarnings.Add(new SigningServer.Android.Com.Android.Apksig.ApkVerificationIssue(issueId, parameters));
        }
        
        /// <summary>
        /// Returns the errors encountered during verification.
        /// </summary>
        public virtual SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.ApkVerificationIssue> GetErrors()
        {
            return mErrors;
        }
        
        /// <summary>
        /// Returns the warnings encountered during verification.
        /// </summary>
        public virtual SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.ApkVerificationIssue> GetWarnings()
        {
            return mWarnings;
        }
        
    }
    
}
