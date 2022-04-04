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
using System.Linq;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.Test.ApkSig.Internal.Util;
using SigningServer.Android.Test.ApkSig.Util;

namespace SigningServer.Android.Test.ApkSig.Apk
{
    [TestClass]
    public class ApkUtilsTest
    {
        [TestMethod]
        public void testGetMinSdkVersionForValidCodename()
        {
            ApkUtils.getMinSdkVersionForCodename("AAAA").Should().Be(1);
            ApkUtils.getMinSdkVersionForCodename("CUPCAKE").Should().Be(1);
            ApkUtils.getMinSdkVersionForCodename("FROYO").Should().Be(7);
            ApkUtils.getMinSdkVersionForCodename("N").Should().Be(23);
            ApkUtils.getMinSdkVersionForCodename("NMR1").Should().Be(23);
            ApkUtils.getMinSdkVersionForCodename("OMG").Should().Be(25);
            // Speculative: Q should be 27 or higher (not yet known at the time of writing)
            ApkUtils.getMinSdkVersionForCodename("QQQ").Should().Be(27);
        }

        [TestMethod]
        [ExpectedException(typeof(CodenameMinSdkVersionException))]
        public void testGetMinSdkVersionForEmptyCodename()
        {
            ApkUtils.getMinSdkVersionForCodename("");
        }

        [TestMethod]
        [ExpectedException(typeof(CodenameMinSdkVersionException))]
        public void testGetMinSdkVersionForUnexpectedCodename()
        {
            ApkUtils.getMinSdkVersionForCodename("1ABC");
        }

        [TestMethod]
        public void testGetMinSdkVersionFromBinaryAndroidManifest()
        {
            ByteBuffer manifest = getAndroidManifest("original.apk");
            Assert.Equals(23, ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(manifest));
        }

        [TestMethod]
        public void testGetDebuggableFromBinaryAndroidManifest()
        {
            ByteBuffer manifest = getAndroidManifest("original.apk");
            ApkUtils.getDebuggableFromBinaryAndroidManifest(manifest).Should().BeFalse();

            manifest = getAndroidManifest("debuggable-boolean.apk");
            ApkUtils.getDebuggableFromBinaryAndroidManifest(manifest).Should().BeTrue();

            // android:debuggable value is a resource reference -- this must be rejected
            manifest = getAndroidManifest("debuggable-resource.apk");
            try
            {
                ApkUtils.getDebuggableFromBinaryAndroidManifest(manifest);
                Assert.Fail();
            }
            catch (ApkFormatException expected)
            {
            }
        }

        [TestMethod]
        public void testGetPackageNameFromBinaryAndroidManifest()
        {
            ByteBuffer manifest = getAndroidManifest("original.apk");
            Assert.Equals(
                "android.appsecurity.cts.tinyapp",
                ApkUtils.getPackageNameFromBinaryAndroidManifest(manifest));
        }

        [TestMethod]
        public void testGetTargetSdkVersionFromBinaryAndroidManifest()
        {
            ByteBuffer manifest = getAndroidManifest("v3-ec-p256-targetSdk-30.apk");
            Assert.Equals(30, ApkUtils.getTargetSdkVersionFromBinaryAndroidManifest(manifest));
        }

        [TestMethod]
        public void testGetTargetSdkVersion_noUsesSdkElement_returnsDefault()
        {
            ByteBuffer manifest = getAndroidManifest("v1-only-no-uses-sdk.apk");
            Assert.Equals(1, ApkUtils.getTargetSdkVersionFromBinaryAndroidManifest(manifest));
        }

        [TestMethod]
        public void testGetTargetSandboxVersionFromBinaryAndroidManifest()
        {
            ByteBuffer manifest = getAndroidManifest("targetSandboxVersion-2.apk");
            Assert.Equals(2, ApkUtils.getTargetSandboxVersionFromBinaryAndroidManifest(manifest));
        }

        [TestMethod]
        public void testGetTargetSandboxVersion_noTargetSandboxAttribute_returnsDefault()
        {
            ByteBuffer manifest = getAndroidManifest("original.apk");
            Assert.Equals(1, ApkUtils.getTargetSandboxVersionFromBinaryAndroidManifest(manifest));
        }

        [TestMethod]
        public void testGetVersionCodeFromBinaryAndroidManifest()
        {
            ByteBuffer manifest = getAndroidManifest("original.apk");
            Assert.Equals(10, ApkUtils.getVersionCodeFromBinaryAndroidManifest(manifest));
        }

        [TestMethod]
        public void testGetVersionCode_withVersionCodeMajor_returnsOnlyVersionCode()
        {
            ByteBuffer manifest = getAndroidManifest("original-with-versionCodeMajor.apk");
            Assert.Equals(25, ApkUtils.getVersionCodeFromBinaryAndroidManifest(manifest));
        }

        [TestMethod]
        public void testGetLongVersionCodeFromBinaryAndroidManifest()
        {
            ByteBuffer manifest = getAndroidManifest("original-with-versionCodeMajor.apk");
            Assert.Equals(4294967321L, ApkUtils.getLongVersionCodeFromBinaryAndroidManifest(manifest));
        }

        [TestMethod]
        public void testGetAndroidManifest()
        {
            ByteBuffer manifest = getAndroidManifest("original.apk");
            var md = SHA256.Create();
            var remaining = new byte[manifest.remaining()];
            manifest.get(remaining);
            byte[] actualDigest = md.ComputeHash(remaining);
            TestHelpers.encodeHex(actualDigest).Should()
                .Be("8b3de63a282652221162cdc327f424924ac3c7c24e642035975a1ee7a395c4dc");
        }

        private static ByteBuffer getAndroidManifest(String apkResourceName)
        {
            return getAndroidManifest(getResource(apkResourceName));
        }

        private static ByteBuffer getAndroidManifest(byte[] apk)
        {
            return ApkUtils.getAndroidManifest(DataSources.asDataSource(ByteBuffer.wrap(apk)));
        }

        private static byte[] getResource(String resourceName)
        {
            return Resources.toByteArray(resourceName);
        }
    }
}