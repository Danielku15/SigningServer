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

namespace SigningServer.Android.ApkSig.Internal.Apk.v1
{
    /** Constants used by the Jar Signing / V1 Signature Scheme signing and verification. */
    public static class V1SchemeConstants
    {
        public static readonly String MANIFEST_ENTRY_NAME = "META-INF/MANIFEST.MF";

        public static readonly String SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME_STR =
            "X-Android-APK-Signed";
    }
}