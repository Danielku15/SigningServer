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

namespace SigningServer.Android.ApkSig.Internal.Util
{
    /**
     * Android SDK version / API Level constants.
     */
    public static class AndroidSdkVersion
    {
        /** Android 1.0 */
        public static readonly int INITIAL_RELEASE = 1;

        /** Android 2.3. */
        public static readonly int GINGERBREAD = 9;

        /** Android 3.0 */
        public static readonly int HONEYCOMB = 11;

        /** Android 4.3. The revenge of the beans. */
        public static readonly int JELLY_BEAN_MR2 = 18;

        /** Android 4.4. KitKat, another tasty treat. */
        public static readonly int KITKAT = 19;

        /** Android 5.0. A flat one with beautiful shadows. But still tasty. */
        public static readonly int LOLLIPOP = 21;

        /** Android 6.0. M is for Marshmallow! */
        public static readonly int M = 23;

        /** Android 7.0. N is for Nougat. */
        public static readonly int N = 24;

        /** Android O. */
        public static readonly int O = 26;

        /** Android P. */
        public static readonly int P = 28;

        /** Android R. */
        public static readonly int R = 30;
    }
}