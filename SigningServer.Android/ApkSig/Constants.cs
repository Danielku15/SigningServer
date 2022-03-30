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

using SigningServer.Android.ApkSig.Internal.Apk.Stamp;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Android.ApkSig.Internal.Apk.v2;
using SigningServer.Android.ApkSig.Internal.Apk.v3;

namespace SigningServer.Android.ApkSig
{
    /**
     * Exports internally defined constants to allow clients to reference these values without relying
     * on internal code.
     */
    public static class Constants
    {
        public static readonly int VERSION_SOURCE_STAMP = 0;
        public static readonly int VERSION_JAR_SIGNATURE_SCHEME = 1;
        public static readonly int VERSION_APK_SIGNATURE_SCHEME_V2 = 2;
        public static readonly int VERSION_APK_SIGNATURE_SCHEME_V3 = 3;
        public static readonly int VERSION_APK_SIGNATURE_SCHEME_V4 = 4;

        public static readonly string MANIFEST_ENTRY_NAME = V1SchemeConstants.MANIFEST_ENTRY_NAME;

        public static readonly int APK_SIGNATURE_SCHEME_V2_BLOCK_ID =
            V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID;

        public static readonly int APK_SIGNATURE_SCHEME_V3_BLOCK_ID =
            V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID;

        public static readonly int PROOF_OF_ROTATION_ATTR_ID = V3SchemeConstants.PROOF_OF_ROTATION_ATTR_ID;

        public static readonly int V1_SOURCE_STAMP_BLOCK_ID =
            SourceStampConstants.V1_SOURCE_STAMP_BLOCK_ID;

        public static readonly int V2_SOURCE_STAMP_BLOCK_ID =
            SourceStampConstants.V2_SOURCE_STAMP_BLOCK_ID;
    }
}