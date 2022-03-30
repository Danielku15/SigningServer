﻿/*
 * Copyright (C) 2018 The Android Open Source Project
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
namespace SigningServer.Android.ApkSig
{
    /**
     * APK Signer Lineage.
     *
     * <p>The signer lineage contains a history of signing certificates with each ancestor attesting to
     * the validity of its descendant.  Each additional descendant represents a new identity that can be
     * used to sign an APK, and each generation has accompanying attributes which represent how the
     * APK would like to view the older signing certificates, specifically how they should be trusted in
     * certain situations.
     *
     * <p> Its primary use is to enable APK Signing Certificate Rotation.  The Android platform verifies
     * the APK Signer Lineage, and if the current signing certificate for the APK is in the Signer
     * Lineage, and the Lineage contains the certificate the platform associates with the APK, it will
     * allow upgrades to the new certificate.
     *
     * @see <a href="https://source.android.com/security/apksigning/index.html">Application Signing</a>
     */
    public class SigningCertificateLineage
    {
        // TODO
        public byte[] encodeSigningCertificateLineage()
        {
            throw new System.NotImplementedException();
        }
    }
}