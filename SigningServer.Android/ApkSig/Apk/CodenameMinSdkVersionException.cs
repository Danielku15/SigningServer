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

namespace SigningServer.Android.ApkSig.Apk
{
    /**
     * Indicates that there was an issue determining the minimum Android platform version supported by
     * an APK because the version is specified as a codename, rather than as API Level number, and the
     * codename is in an unexpected format.
     */
    public class CodenameMinSdkVersionException : MinSdkVersionException
    {
        /** Encountered codename. */
        private readonly string mCodename;

        /**
         * Constructs a new {@code MinSdkVersionCodenameException} with the provided message and
         * codename.
         */
        public CodenameMinSdkVersionException(string message, string codename) : base(message)
        {
            mCodename = codename;
        }

        /**
         * Returns the codename.
         */
        public string getCodename()
        {
            return mCodename;
        }
    }
}