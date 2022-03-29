﻿/*
 * Copyright (C) 2017 The Android Open Source Project
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
     * Indicates that no APK Signing Block was found in an APK.
     */
    public class ApkSigningBlockNotFoundException : Exception
    {
        public ApkSigningBlockNotFoundException(string message) : base(message)
        {
        }

        public ApkSigningBlockNotFoundException(string message, Exception innerException) : base(message,
            innerException)
        {
        }
    }
}