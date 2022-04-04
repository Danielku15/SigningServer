/*
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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.v3;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.Test.ApkSig.Internal.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig
{
    [TestClass]
    public class SigningCertificateLineageTest
    {
        // createLineageWithSignersFromResources and updateLineageWithSignerFromResources will add the
        // SignerConfig for the signers added to the Lineage to this list.
        private List<SigningCertificateLineage.SignerConfig> mSigners;

        // All signers with the same prefix and an _X suffix were signed with the private key of the
        // (X-1) signer.
        private static readonly String FIRST_RSA_1024_SIGNER_RESOURCE_NAME = "rsa-1024";
        private static readonly String SECOND_RSA_1024_SIGNER_RESOURCE_NAME = "rsa-1024_2";

        private static readonly String FIRST_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048";
        private static readonly String SECOND_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048_2";
        private static readonly String THIRD_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048_3";

        [TestInitialize]
        public void setUp()
        {
            mSigners = new List<SigningCertificateLineage.SignerConfig>();
        }

        [TestMethod]
        public void testFirstRotationContainsExpectedSigners()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            assertLineageContainsExpectedSigners(lineage, mSigners);
            SigningCertificateLineage.SignerConfig unknownSigner =
                Resources.toLineageSignerConfig(THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            assertFalse("The signer " + unknownSigner.getCertificate().getSubjectDN()
                                      + " should not be in the lineage", lineage.isSignerInLineage(unknownSigner));
        }

        [TestMethod]
        public void testRotationWithExistingLineageContainsExpectedSigners()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            lineage = updateLineageWithSignerFromResources(lineage,
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            assertLineageContainsExpectedSigners(lineage, mSigners);
        }

        [TestMethod]
        public void testLineageFromBytesContainsExpectedSigners()
        {
            // This file contains the lineage with the three rsa-2048 signers
            DataSource lineageDataSource = Resources.toDataSource("rsa-2048-lineage-3-signers");
            SigningCertificateLineage lineage = SigningCertificateLineage.readFromBytes(
                lineageDataSource.getByteBuffer(0, (int)lineageDataSource.size()).array());
            List<SigningCertificateLineage.SignerConfig> signers = new List<SigningCertificateLineage.SignerConfig>(3);
            signers.Add(
                Resources.toLineageSignerConfig(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
            signers.Add(
                Resources.toLineageSignerConfig(SECOND_RSA_2048_SIGNER_RESOURCE_NAME));
            signers.Add(
                Resources.toLineageSignerConfig(THIRD_RSA_2048_SIGNER_RESOURCE_NAME));
            assertLineageContainsExpectedSigners(lineage, signers);
        }

        [TestMethod]
        public void testLineageFromFileContainsExpectedSigners()
        {
            // This file contains the lineage with the three rsa-2048 signers
            DataSource lineageDataSource = Resources.toDataSource("rsa-2048-lineage-3-signers");
            SigningCertificateLineage lineage = SigningCertificateLineage.readFromDataSource(
                lineageDataSource);
            List<SigningCertificateLineage.SignerConfig> signers = new List<SigningCertificateLineage.SignerConfig>(3);
            signers.Add(
                Resources.toLineageSignerConfig(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
            signers.Add(
                Resources.toLineageSignerConfig(SECOND_RSA_2048_SIGNER_RESOURCE_NAME));
            signers.Add(
                Resources.toLineageSignerConfig(THIRD_RSA_2048_SIGNER_RESOURCE_NAME));
            assertLineageContainsExpectedSigners(lineage, signers);
        }

        [TestMethod]
        public void testLineageFromFileDoesNotContainUnknownSigner()
        {
            // This file contains the lineage with the first two rsa-2048 signers
            SigningCertificateLineage lineage = Resources.toSigningCertificateLineage(
                "rsa-2048-lineage-2-signers");
            SigningCertificateLineage.SignerConfig unknownSigner = Resources.toLineageSignerConfig(
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            assertFalse("The signer " + unknownSigner.getCertificate().getSubjectDN()
                                      + " should not be in the lineage", lineage.isSignerInLineage(unknownSigner));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void testLineageFromFileWithInvalidMagicFails()
        {
            // This file contains the lineage with two rsa-2048 signers and a modified MAGIC value
            Resources.toSigningCertificateLineage("rsa-2048-lineage-invalid-magic");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void testLineageFromFileWithInvalidVersionFails()
        {
            // This file contains the lineage with two rsa-2048 signers and an invalid value of FF for
            // the version
            Resources.toSigningCertificateLineage("rsa-2048-lineage-invalid-version");
        }

        [TestMethod]
        public void testLineageWrittenToBytesContainsExpectedSigners()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            lineage = updateLineageWithSignerFromResources(lineage,
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            byte[] lineageBytes = lineage.getBytes();
            lineage = SigningCertificateLineage.readFromBytes(lineageBytes);
            assertLineageContainsExpectedSigners(lineage, mSigners);
        }

        [TestMethod]
        public void testLineageWrittenToFileContainsExpectedSigners()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            lineage = updateLineageWithSignerFromResources(lineage,
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            FileInfo lineageFile = new FileInfo(Path.GetTempFileName());
            try
            {
                lineage.writeToFile(lineageFile);
                lineage = SigningCertificateLineage.readFromFile(lineageFile);
                assertLineageContainsExpectedSigners(lineage, mSigners);
            }
            finally
            {
                lineageFile.Delete();
            }
        }

        [TestMethod]
        public void testUpdatedCapabilitiesInLineage()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage.SignerConfig oldSignerConfig = mSigners[0];
            List<Boolean> expectedCapabilityValues = new List<bool>
            {
                false, false, false, false, false
            };
            SigningCertificateLineage.SignerCapabilities newCapabilities =
                buildSignerCapabilities(expectedCapabilityValues);
            lineage.updateSignerCapabilities(oldSignerConfig, newCapabilities);
            SigningCertificateLineage.SignerCapabilities updatedCapabilities =
                lineage.getSignerCapabilities(oldSignerConfig);
            assertExpectedCapabilityValues(updatedCapabilities, expectedCapabilityValues);
        }

        [TestMethod]
        public void testUpdatedCapabilitiesInLineageWrittenToFile()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage.SignerConfig oldSignerConfig = mSigners[0];
            List<Boolean> expectedCapabilityValues = new List<bool>
            {
                false, false, false, false, false
            };
            SigningCertificateLineage.SignerCapabilities newCapabilities =
                buildSignerCapabilities(expectedCapabilityValues);
            lineage.updateSignerCapabilities(oldSignerConfig, newCapabilities);
            FileInfo lineageFile = new FileInfo(Path.GetTempFileName());
            try
            {
                lineage.writeToFile(lineageFile);
                lineage = SigningCertificateLineage.readFromFile(lineageFile);
                SigningCertificateLineage.SignerCapabilities updatedCapabilities =
                    lineage.getSignerCapabilities(oldSignerConfig);
                assertExpectedCapabilityValues(updatedCapabilities, expectedCapabilityValues);
            }
            finally
            {
                lineageFile.Delete();
            }
        }

        [TestMethod]
        public void testCapabilitiesAreNotUpdatedWithDefaultValues()
        {
            // This file contains the lineage with the first two rsa-2048 signers with the first signer
            // having all of the capabilities set to false.
            SigningCertificateLineage lineage = Resources.toSigningCertificateLineage(
                "rsa-2048-lineage-no-capabilities-first-signer");
            List<Boolean> expectedCapabilityValues = new List<bool>
            {
                false, false, false, false, false
            };
            SigningCertificateLineage.SignerConfig oldSignerConfig = Resources.toLineageSignerConfig(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage.SignerCapabilities oldSignerCapabilities =
                lineage.getSignerCapabilities(oldSignerConfig);
            assertExpectedCapabilityValues(oldSignerCapabilities, expectedCapabilityValues);
            // The builder is called directly to ensure all of the capabilities are set to the default
            // values and the caller configured flags are not modified in this SignerCapabilities.
            SigningCertificateLineage.SignerCapabilities newCapabilities =
                new SigningCertificateLineage.SignerCapabilities.Builder().build();
            lineage.updateSignerCapabilities(oldSignerConfig, newCapabilities);
            SigningCertificateLineage.SignerCapabilities updatedCapabilities =
                lineage.getSignerCapabilities(oldSignerConfig);
            assertExpectedCapabilityValues(updatedCapabilities, expectedCapabilityValues);
        }

        [TestMethod]
        public void testFirstRotationWitNonDefaultCapabilitiesForSigners()
        {
            SigningCertificateLineage.SignerConfig oldSigner = Resources.toLineageSignerConfig(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage.SignerConfig newSigner = Resources.toLineageSignerConfig(
                SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            List<Boolean> oldSignerCapabilityValues = new List<bool>
            {
                false, false, false, false, false
            };
            List<Boolean> newSignerCapabilityValues = new List<bool> { false, true, false, false, false };
            SigningCertificateLineage lineage = new SigningCertificateLineage.Builder(oldSigner,
                    newSigner)
                .setOriginalCapabilities(buildSignerCapabilities(oldSignerCapabilityValues))
                .setNewCapabilities(buildSignerCapabilities(newSignerCapabilityValues))
                .build();
            SigningCertificateLineage.SignerCapabilities oldSignerCapabilities =
                lineage.getSignerCapabilities(oldSigner);
            assertExpectedCapabilityValues(oldSignerCapabilities, oldSignerCapabilityValues);
            SigningCertificateLineage.SignerCapabilities newSignerCapabilities =
                lineage.getSignerCapabilities(newSigner);
            assertExpectedCapabilityValues(newSignerCapabilities, newSignerCapabilityValues);
        }

        [TestMethod]
        public void testRotationWithExitingLineageAndNonDefaultCapabilitiesForNewSigner()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage.SignerConfig oldSigner = mSigners.Last();
            SigningCertificateLineage.SignerConfig newSigner = Resources.toLineageSignerConfig(
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            List<Boolean> newSignerCapabilityValues = new List<bool> { false, false, false, false, false };
            lineage = lineage.spawnDescendant(oldSigner, newSigner,
                buildSignerCapabilities(newSignerCapabilityValues));
            SigningCertificateLineage.SignerCapabilities newSignerCapabilities =
                lineage.getSignerCapabilities(newSigner);
            assertExpectedCapabilityValues(newSignerCapabilities, newSignerCapabilityValues);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void testRotationWithExistingLineageUsingNonParentSignerFails()
        {
            // When rotating the signing certificate the most recent signer must be provided to the
            // spawnDescendant method. This test ensures that using an ancestor of the most recent
            // signer will fail as expected.
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage.SignerConfig oldestSigner = mSigners[0];
            SigningCertificateLineage.SignerConfig newSigner = Resources.toLineageSignerConfig(
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            lineage.spawnDescendant(oldestSigner, newSigner);
        }

        [TestMethod]
        public void testLineageFromV3SignerAttribute()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            // The format of the V3 Signer Attribute is as follows (little endian):
            // * length-prefixed bytes: attribute pair
            //   * uint32: ID
            //   * bytes: value - encoded V3 SigningCertificateLineage
            ByteBuffer v3SignerAttribute = ByteBuffer.wrap(
                V3SchemeSigner.generateV3SignerAttribute(lineage));
            v3SignerAttribute.order(ByteOrder.LITTLE_ENDIAN);
            ByteBuffer attribute = ApkSigningBlockUtils.getLengthPrefixedSlice(v3SignerAttribute);
            // The generateV3SignerAttribute method should only use the PROOF_OF_ROTATION_ATTR_ID
            // value for the ID.
            int id = attribute.getInt();
            assertEquals(
                "The ID of the v3SignerAttribute ByteBuffer is not the expected "
                + "PROOF_OF_ROTATION_ATTR_ID",
                V3SchemeConstants.PROOF_OF_ROTATION_ATTR_ID, id);
            lineage = SigningCertificateLineage.readFromV3AttributeValue(
                ByteBufferUtils.toByteArray(attribute));
            assertLineageContainsExpectedSigners(lineage, mSigners);
        }

        [TestMethod]
        public void testSortedSignerConfigsAreInSortedOrder()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            DefaultApkSignerEngine.SignerConfig oldSigner = getApkSignerEngineSignerConfigFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            DefaultApkSignerEngine.SignerConfig newSigner = getApkSignerEngineSignerConfigFromResources(
                SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            List<DefaultApkSignerEngine.SignerConfig> signers = new List<DefaultApkSignerEngine.SignerConfig>
            {
                newSigner, oldSigner
            };
            List<DefaultApkSignerEngine.SignerConfig> sortedSigners = lineage.sortSignerConfigs(
                signers);
            assertEquals("The sorted signer list does not contain the expected number of elements",
                signers.Count, sortedSigners.Count);
            assertEquals("The first element in the sorted list should be the first signer", oldSigner,
                sortedSigners[0]);
            assertEquals("The second element in the sorted list should be the second signer", newSigner,
                sortedSigners[1]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void testSortedSignerConfigsWithUnknownSignerFails()
        {
            // Since this test includes a signer that is not in the lineage the sort should fail with
            // an IllegalArgumentException.
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            DefaultApkSignerEngine.SignerConfig oldSigner = getApkSignerEngineSignerConfigFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            DefaultApkSignerEngine.SignerConfig newSigner = getApkSignerEngineSignerConfigFromResources(
                SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            DefaultApkSignerEngine.SignerConfig unknownSigner =
                getApkSignerEngineSignerConfigFromResources(THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            List<DefaultApkSignerEngine.SignerConfig> signers = new List<DefaultApkSignerEngine.SignerConfig>
            {
                newSigner, oldSigner,
                unknownSigner
            };
            lineage.sortSignerConfigs(signers);
        }

        [TestMethod]
        public void testAllExpectedCertificatesAreInLineage()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            lineage = updateLineageWithSignerFromResources(lineage,
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            ISet<X509Certificate> expectedCertSet = new HashSet<X509Certificate>();
            for (int i = 0; i < mSigners.Count; i++)
            {
                expectedCertSet.Add(mSigners[i].getCertificate());
            }

            List<X509Certificate> certs = lineage.getCertificatesInLineage();
            assertEquals(
                "The number of elements in the certificate list from the lineage does not equal "
                + "the expected number",
                expectedCertSet.Count, certs.Count);
            foreach (X509Certificate cert in certs)
            {
                // remove the certificate from the Set to ensure duplicate certs were not returned.
                assertTrue("An unexpected certificate, " + cert.getSubjectDN() + ", is in the lineage",
                    expectedCertSet.Remove(cert));
            }
        }

        [TestMethod]
        public void testSublineageContainsExpectedSigners()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            lineage = updateLineageWithSignerFromResources(lineage,
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            List<SigningCertificateLineage.SignerConfig> subList = mSigners.GetRange(0, 2);
            X509Certificate cert = subList[1].getCertificate();
            SigningCertificateLineage subLineage = lineage.getSubLineage(cert);
            assertLineageContainsExpectedSigners(subLineage, subList);
        }

        [TestMethod]
        public void testConsolidatedLineageContainsExpectedSigners()
        {
            SigningCertificateLineage lineage = createLineageWithSignersFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage updatedLineage = updateLineageWithSignerFromResources(lineage,
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            List<SigningCertificateLineage> lineages = new List<SigningCertificateLineage>
            {
                lineage, updatedLineage
            };
            SigningCertificateLineage consolidatedLineage =
                SigningCertificateLineage.consolidateLineages(lineages);
            assertLineageContainsExpectedSigners(consolidatedLineage, mSigners);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void testConsolidatedLineageWithDisjointLineagesFail()
        {
            List<SigningCertificateLineage> lineages = new List<SigningCertificateLineage>();
            lineages.Add(createLineageWithSignersFromResources(FIRST_RSA_1024_SIGNER_RESOURCE_NAME,
                SECOND_RSA_1024_SIGNER_RESOURCE_NAME));
            lineages.Add(createLineageWithSignersFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME,
                SECOND_RSA_2048_SIGNER_RESOURCE_NAME));
            SigningCertificateLineage.consolidateLineages(lineages);
        }

        [TestMethod]
        public void testLineageFromAPKContainsExpectedSigners()
        {
            SigningCertificateLineage.SignerConfig firstSigner = getSignerConfigFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage.SignerConfig secondSigner = getSignerConfigFromResources(
                SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage.SignerConfig thirdSigner = getSignerConfigFromResources(
                THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            List<SigningCertificateLineage.SignerConfig> expectedSigners =
                new List<SigningCertificateLineage.SignerConfig>
                {
                    firstSigner, secondSigner, thirdSigner
                };
            DataSource apkDataSource = Resources.toDataSource(
                "v1v2v3-with-rsa-2048-lineage-3-signers.apk");
            SigningCertificateLineage lineageFromApk = SigningCertificateLineage.readFromApkDataSource(
                apkDataSource);
            assertLineageContainsExpectedSigners(lineageFromApk, expectedSigners);
        }

        [TestMethod]
        [ExpectedException(typeof(ApkFormatException))]
        public void testLineageFromAPKWithInvalidZipCDSizeFails()
        {
            // This test verifies that attempting to read the lineage from an APK where the zip
            // sections cannot be parsed fails. This APK is based off the
            // v1v2v3-with-rsa-2048-lineage-3-signers.apk with a modified CD size in the EoCD.
            DataSource apkDataSource = Resources.toDataSource(
                "v1v2v3-with-rsa-2048-lineage-3-signers-invalid-zip.apk");
            SigningCertificateLineage.readFromApkDataSource(apkDataSource);
        }

        [TestMethod]
        public void testLineageFromAPKWithNoLineageFails()
        {
            // This test verifies that attempting to read the lineage from an APK without a lineage
            // fails.
            // This is a valid APK that has only been signed with the V1 and V2 signature schemes;
            // since the lineage is an attribute in the V3 signature block this test should fail.
            DataSource apkDataSource = Resources.toDataSource(
                "golden-aligned-v1v2-out.apk");
            try
            {
                SigningCertificateLineage.readFromApkDataSource(apkDataSource);
                fail("A failure should have been reported due to the APK not containing a V3 signing "
                     + "block");
            }
            catch (ArgumentException expected)
            {
            }

            // This is a valid APK signed with the V1, V2, and V3 signature schemes, but there is no
            // lineage in the V3 signature block.
            apkDataSource = Resources.toDataSource("golden-aligned-v1v2v3-out.apk");
            try
            {
                SigningCertificateLineage.readFromApkDataSource(apkDataSource);
                fail("A failure should have been reported due to the APK containing a V3 signing "
                     + "block without the lineage attribute");
            }
            catch (ArgumentException expected)
            {
            }

            // This APK is based off the v1v2v3-with-rsa-2048-lineage-3-signers.apk with a bit flip
            // in the lineage attribute ID in the V3 signature block.
            apkDataSource = Resources.toDataSource(
                "v1v2v3-with-rsa-2048-lineage-3-signers-invalid-lineage-attr.apk");
            try
            {
                SigningCertificateLineage.readFromApkDataSource(apkDataSource);
                fail("A failure should have been reported due to the APK containing a V3 signing "
                     + "block with a modified lineage attribute ID");
            }
            catch (ArgumentException expected)
            {
            }
        }

        /**
     * Builds a new {@code SigningCertificateLinage.SignerCapabilities} object using the values in
     * the provided {@code List}. The {@code List} should contain {@code boolean} values to be
     * passed to the following methods in the
     * {@code SigningCertificateLineage.SignerCapabilities.Builder} (if a value is not provided the
     * noted default is used):
     *
     *  {@code SigningCertificateLineage.SignerCapabilities.Builder.setInstalledData} [{@code true}]
     *  {@code SigningCertificateLineage.SignerCapabilities.Builder.setSharedUid} [{@code true}]
     *  {@code SigningCertificateLineage.SignerCapabilities.Builder.setPermission} [{@code true}]
     *  {@code SigningCertificateLineage.SignerCapabilities.Builder.setRollback} [{@code false}]
     *  {@code SigningCertificateLineage.SignerCapabilities.Builder.setAuth} [{@code true}]
     *
     * This method should not be used when testing caller configured capabilities since the setXX
     * method for each capability is called.
     */
        private SigningCertificateLineage.SignerCapabilities buildSignerCapabilities(List<Boolean> capabilityValues)
        {
            return new SigningCertificateLineage.SignerCapabilities.Builder()
                .setInstalledData(capabilityValues.Count > 0 ? capabilityValues[0] : true)
                .setSharedUid(capabilityValues.Count > 1 ? capabilityValues[1] : true)
                .setPermission(capabilityValues.Count > 2 ? capabilityValues[2] : true)
                .setRollback(capabilityValues.Count > 3 ? capabilityValues[3] : false)
                .setAuth(capabilityValues.Count > 4 ? capabilityValues[4] : true)
                .build();
        }

        /**
     * Verifies the specified {@code SigningCertificateLinage.SignerCapabilities} contains the
     * expected values from the provided {@code List}. The {@code List} should contain
     * {@code boolean} values to be verified against the
     * {@code SigningCertificateLinage.SignerCapabilities} methods in the following order:
     *
     *  {@mcode SigningCertificateLineage.SignerCapabilities.hasInstalledData}
     *  {@mcode SigningCertificateLineage.SignerCapabilities.hasSharedUid}
     *  {@mcode SigningCertificateLineage.SignerCapabilities.hasPermission}
     *  {@mcode SigningCertificateLineage.SignerCapabilities.hasRollback}
     *  {@mcode SigningCertificateLineage.SignerCapabilities.hasAuth}
     */
        private void assertExpectedCapabilityValues(SigningCertificateLineage.SignerCapabilities capabilities,
            List<Boolean> expectedCapabilityValues)
        {
            assertTrue("The expectedCapabilityValues do not contain the expected number of elements",
                expectedCapabilityValues.Count >= 5);
            assertEquals(
                "The installed data capability is not set to the expected value",
                expectedCapabilityValues[0], capabilities.hasInstalledData());
            assertEquals(
                "The shared UID capability is not set to the expected value",
                expectedCapabilityValues[1], capabilities.hasSharedUid());
            assertEquals(
                "The permission capability is not set to the expected value",
                expectedCapabilityValues[2], capabilities.hasPermission());
            assertEquals(
                "The rollback capability is not set to the expected value",
                expectedCapabilityValues[3], capabilities.hasRollback());
            assertEquals(
                "The auth capability is not set to the expected value",
                expectedCapabilityValues[4], capabilities.hasAuth());
        }

        /**
     * Creates a new {@code SigningCertificateLineage} with the specified signers from the
     * resources. {@code mSigners} will be updated with the
     * {@code SigningCertificateLineage.SignerConfig} for each signer added to the lineage.
     */
        private SigningCertificateLineage createLineageWithSignersFromResources(
            String oldSignerResourceName, String newSignerResourceName)
        {
            SigningCertificateLineage.SignerConfig oldSignerConfig = Resources.toLineageSignerConfig(
                oldSignerResourceName);
            mSigners.Add(oldSignerConfig);
            SigningCertificateLineage.SignerConfig newSignerConfig = Resources.toLineageSignerConfig(
                newSignerResourceName);
            mSigners.Add(newSignerConfig);
            return new SigningCertificateLineage.Builder(oldSignerConfig, newSignerConfig).build();
        }

        /**
     * Updates the specified {@code SigningCertificateLineage} with the signer from the resources.
     * Requires that the {@code mSigners} list contains the previous signers in the lineage since
     * the most recent signer must be specified when adding a new signer to the lineage.
     */
        private SigningCertificateLineage updateLineageWithSignerFromResources(
            SigningCertificateLineage lineage, String newSignerResourceName)
        {
            // To add a new Signer to an existing lineage the config of the last signer must be
            // specified. If this class was used to create the lineage then the last signer should
            // be in the mSigners list.
            assertTrue("The mSigners list did not contain the expected signers to update the lineage",
                mSigners.Count >= 2);
            SigningCertificateLineage.SignerConfig oldSignerConfig = mSigners.Last();
            SigningCertificateLineage.SignerConfig newSignerConfig = Resources.toLineageSignerConfig(
                newSignerResourceName);
            mSigners.Add(newSignerConfig);
            return lineage.spawnDescendant(oldSignerConfig, newSignerConfig);
        }

        private void assertLineageContainsExpectedSigners(SigningCertificateLineage lineage,
            List<SigningCertificateLineage.SignerConfig> signers)
        {
            assertEquals("The lineage does not contain the expected number of signers",
                signers.Count, lineage.size());
            foreach (SigningCertificateLineage.SignerConfig signer in
                     signers)
            {
                assertTrue("The signer " + signer.getCertificate().getSubjectDN()
                                         + " is expected to be in the lineage", lineage.isSignerInLineage(signer));
            }
        }

        private static SigningCertificateLineage.SignerConfig getSignerConfigFromResources(
            String resourcePrefix)
        {
            PrivateKey privateKey = Resources.toPrivateKey(resourcePrefix + ".pk8");
            X509Certificate cert = Resources.toCertificate(resourcePrefix + ".x509.pem");
            return new SigningCertificateLineage.SignerConfig.Builder(privateKey, cert).build();
        }

        private static DefaultApkSignerEngine.SignerConfig getApkSignerEngineSignerConfigFromResources(
            String resourcePrefix)
        {
            PrivateKey privateKey = Resources.toPrivateKey(resourcePrefix + ".pk8");
            X509Certificate cert = Resources.toCertificate(resourcePrefix + ".x509.pem");
            return new DefaultApkSignerEngine.SignerConfig.Builder(resourcePrefix, privateKey,
                new List<X509Certificate>
                {
                    cert
                }).build();
        }
    }
}