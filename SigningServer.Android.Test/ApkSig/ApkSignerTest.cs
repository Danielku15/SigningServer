/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except @in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to @in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using ICSharpCode.SharpZipLib.Zip;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig;
using SigningServer.Android.ApkSig.Apk;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.Stamp;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Android.ApkSig.Internal.Apk.v2;
using SigningServer.Android.ApkSig.Internal.Apk.v3;
using SigningServer.Android.ApkSig.Internal.Asn1;
using SigningServer.Android.ApkSig.Internal.Util;
using SigningServer.Android.ApkSig.Internal.X509;
using SigningServer.Android.ApkSig.Internal.Zip;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;
using SigningServer.Android.Test.ApkSig.Internal.Util;
using static SigningServer.Android.Test.ApkSig.Util.TestHelpers;

namespace SigningServer.Android.Test.ApkSig
{
    [TestClass]
    public class ApkSignerTest
    {
        /**
     * Whether to preserve, as files, outputs of failed tests. This is useful for investigating test
     * failures.
     */
        private static readonly bool KEEP_FAILING_OUTPUT_AS_FILES = false;

        // All signers with the same prefix and an _X suffix were signed with the private key of the
        // (X-1) signer.
        private static readonly String FIRST_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048";
        private static readonly String SECOND_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048_2";
        private static readonly String THIRD_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048_3";

        private static readonly String EC_P256_SIGNER_RESOURCE_NAME = "ec-p256";

        // This is the same cert as above with the modulus reencoded to remove the leading 0 sign bit.
        private static readonly String FIRST_RSA_2048_SIGNER_CERT_WITH_NEGATIVE_MODULUS =
            "rsa-2048_negmod.x509.der";

        private static readonly String LINEAGE_RSA_2048_2_SIGNERS_RESOURCE_NAME =
            "rsa-2048-lineage-2-signers";

        // These are the ID and value of an extra signature block within the APK signing block that
        // can be preserved through the setOtherSignersSignaturesPreserved API.
        private readonly int EXTRA_BLOCK_ID = 0x7e57c0de;
        private readonly byte[] EXTRA_BLOCK_VALUE = { 0, 1, 2, 3, 4, 5, 6, 7 };

        public static void Main(String[] args)
        {
            DirectoryInfo outDir = (args.Length > 0) ? new DirectoryInfo(args[0]) : new DirectoryInfo(".");
            generateGoldenFiles(outDir);
        }

        private static void generateGoldenFiles(DirectoryInfo outDir)
        {
            Console.WriteLine(
                "Generating golden files "
                + typeof(ApkSignerTest).Name
                + " into "
                + outDir);
            if (!outDir.Exists)
            {
                Directory.CreateDirectory(outDir.FullName);
            }

            List<ApkSigner.SignerConfig> rsa2048SignerConfig =
                new List<ApkSigner.SignerConfig>
                {
                    getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME)
                };
            List<ApkSigner.SignerConfig> rsa2048SignerConfigWithLineage =
                new List<ApkSigner.SignerConfig>
                {
                    rsa2048SignerConfig[0],
                    getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME)
                };
            SigningCertificateLineage lineage =
                Resources.toSigningCertificateLineage(LINEAGE_RSA_2048_2_SIGNERS_RESOURCE_NAME);

            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig));

            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-v1-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-v1-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-v1-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false));

            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-v2-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-v2-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-v2-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));

            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-v3-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-v3-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-v3-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true));

            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-v3-lineage-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-v3-lineage-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-v3-lineage-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));

            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-v1v2-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-v1v2-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-v1v2-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));

            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-v2v3-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-v2v3-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-v2v3-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-v2v3-lineage-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-v2v3-lineage-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-v2v3-lineage-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));

            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-v1v2v3-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-v1v2v3-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-v1v2v3-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            signGolden(
                "golden-unaligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-unaligned-v1v2v3-lineage-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            signGolden(
                "golden-legacy-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-legacy-aligned-v1v2v3-lineage-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            signGolden(
                "golden-aligned-in.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-aligned-v1v2v3-lineage-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));

            signGolden(
                "original.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-rsa-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig));
            signGolden(
                "original.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-rsa-minSdkVersion-1-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig).setMinSdkVersion(1));
            signGolden(
                "original.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-rsa-minSdkVersion-18-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig).setMinSdkVersion(18));
            signGolden(
                "original.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-rsa-minSdkVersion-24-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig).setMinSdkVersion(24));
            signGolden(
                "original.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-rsa-verity-@out.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setVerityEnabled(true));

            signGolden(
                "pinsapp-unsigned.apk",
                new FileInfo(Path.Combine(outDir.FullName, "golden-pinsapp-signed.apk")),
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setVerityEnabled(true));
        }

        private static void signGolden(
            String inResourceName, FileInfo outFile, ApkSigner.Builder apkSignerBuilder)
        {
            DataSource @in =
                DataSources.asDataSource(
                    ByteBuffer.wrap(Resources.toByteArray(inResourceName)));
            apkSignerBuilder.setInputApk(@in).setOutputApk(outFile);

            var outFileIdSig = new FileInfo(outFile.FullName + ".idsig");
            apkSignerBuilder.setV4SignatureOutputFile(outFileIdSig);
            apkSignerBuilder.setV4ErrorReportingEnabled(true);

            apkSignerBuilder.build().sign();
        }

        [TestMethod]
        public void testAlignmentPreserved_Golden()
        {
            // Regression tests for preserving (mis)alignment of ZIP Local FileInfo Header data
            // NOTE: Expected output files can be re-generated by running the "main" method.

            List<ApkSigner.SignerConfig> rsa2048SignerConfig =
                new List<ApkSigner.SignerConfig>
                {
                    getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME)
                };
            List<ApkSigner.SignerConfig> rsa2048SignerConfigWithLineage =
                new List<ApkSigner.SignerConfig>
                {
                    rsa2048SignerConfig[0],
                    getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME)
                };
            SigningCertificateLineage lineage =
                Resources.toSigningCertificateLineage(
                    LINEAGE_RSA_2048_2_SIGNERS_RESOURCE_NAME);
            // Uncompressed entries @in this input file are not aligned -- the file was created using
            // the jar utility. temp4.txt entry was then manually added into the archive. This entry's
            // ZIP Local FileInfo Header "extra" field declares that the entry's data must be aligned to
            // 4 kB boundary, but the data isn't actually aligned @in the file.
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig));
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v1-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false));
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v2-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v3-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true));
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v3-lineage-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v1v2-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v2v3-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v2v3-lineage-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v1v2v3-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v1v2v3-lineage-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));

            // Uncompressed entries @in this input file are aligned by zero-padding the "extra" field, as
            // performed by zipalign at the time of writing. This padding technique produces ZIP
            // archives whose "extra" field are not compliant with APPNOTE.TXT. Hence, this technique
            // was deprecated.
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig));
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v1-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false));
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v2-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v3-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true));
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v3-lineage-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v1v2-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v2v3-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v2v3-lineage-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v1v2v3-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v1v2v3-lineage-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));

            // Uncompressed entries @in this input file are aligned by padding the "extra" field, as
            // generated by signapk and apksigner. This padding technique produces "extra" fields which
            // are compliant with APPNOTE.TXT.
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig));
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v1-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false));
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v2-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v3-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true));
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v3-lineage-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v1v2-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false));
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v2v3-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v2v3-lineage-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v1v2v3-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true));
            assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v1v2v3-lineage-@out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
        }

        [TestMethod]
        public void testMinSdkVersion_Golden()
        {
            // Regression tests for minSdkVersion-based signature/digest algorithm selection
            // NOTE: Expected output files can be re-generated by running the "main" method.

            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> rsaSignerConfig =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            assertGolden("original.apk", "golden-rsa-@out.apk", new ApkSigner.Builder(rsaSignerConfig));
            assertGolden(
                "original.apk",
                "golden-rsa-minSdkVersion-1-@out.apk",
                new ApkSigner.Builder(rsaSignerConfig).setMinSdkVersion(1));
            assertGolden(
                "original.apk",
                "golden-rsa-minSdkVersion-18-@out.apk",
                new ApkSigner.Builder(rsaSignerConfig).setMinSdkVersion(18));
            assertGolden(
                "original.apk",
                "golden-rsa-minSdkVersion-24-@out.apk",
                new ApkSigner.Builder(rsaSignerConfig).setMinSdkVersion(24));

            // TODO: Add tests for DSA and ECDSA. This is non-trivial because the default
            // implementations of these signature algorithms are non-deterministic which means output
            // files always differ from golden files.
        }

        [TestMethod]
        public void testVerityEnabled_Golden()
        {
            List<ApkSigner.SignerConfig> rsaSignerConfig =
                new List<ApkSigner.SignerConfig>
                {
                    getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME)
                };

            assertGolden(
                "original.apk",
                "golden-rsa-verity-@out.apk",
                new ApkSigner.Builder(rsaSignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setVerityEnabled(true));
        }

        [TestMethod]
        public void testRsaSignedVerifies()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            String @in = "original.apk";

            // Sign so that the APK is guaranteed to verify on API Level 1+
            FileInfo @out = sign(@in, new ApkSigner.Builder(signers).setMinSdkVersion(1));
            assertVerified(verifyForMinSdkVersion(@out, 1));

            // Sign so that the APK is guaranteed to verify on API Level 18+
            @out = sign(@in, new ApkSigner.Builder(signers).setMinSdkVersion(18));
            assertVerified(verifyForMinSdkVersion(@out, 18));
            // Does not verify on API Level 17 because RSA with SHA-256 not supported
            assertVerificationFailure(
                verifyForMinSdkVersion(@out, 17), ApkVerifier.Issue.JAR_SIG_UNSUPPORTED_SIG_ALG);
        }

        [TestMethod]
        public void testDsaSignedVerifies()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources("dsa-1024");
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            String @in = "original.apk";

            // Sign so that the APK is guaranteed to verify on API Level 1+
            FileInfo @out = sign(@in, new ApkSigner.Builder(signers).setMinSdkVersion(1));
            assertVerified(verifyForMinSdkVersion(@out, 1));

            // Sign so that the APK is guaranteed to verify on API Level 21+
            @out = sign(@in, new ApkSigner.Builder(signers).setMinSdkVersion(21));
            assertVerified(verifyForMinSdkVersion(@out, 21));
            // Does not verify on API Level 20 because DSA with SHA-256 not supported
            assertVerificationFailure(
                verifyForMinSdkVersion(@out, 20), ApkVerifier.Issue.JAR_SIG_UNSUPPORTED_SIG_ALG);
        }


        [TestMethod]
        public void testDeterministicDsaSignedVerifies()
        {
            ApkSigner.SignerConfig item = getDeterministicDsaSignerConfigFromResources("dsa-2048");
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            String @in = "original.apk";

            // Sign so that the APK is guaranteed to verify on API Level 1+
            FileInfo @out = sign(@in, new ApkSigner.Builder(signers).setMinSdkVersion(1));
            assertVerified(verifyForMinSdkVersion(@out, 1));

            // Sign so that the APK is guaranteed to verify on API Level 21+
            @out = sign(@in, new ApkSigner.Builder(signers).setMinSdkVersion(21));
            assertVerified(verifyForMinSdkVersion(@out, 21));
            // Does not verify on API Level 20 because DSA with SHA-256 not supported
            assertVerificationFailure(
                verifyForMinSdkVersion(@out, 20), ApkVerifier.Issue.JAR_SIG_UNSUPPORTED_SIG_ALG);
        }

        [TestMethod]
        public void testDeterministicDsaSigningIsDeterministic()
        {
            ApkSigner.SignerConfig item = getDeterministicDsaSignerConfigFromResources("dsa-2048");
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            String @in = "original.apk";

            ApkSigner.Builder apkSignerBuilder = new ApkSigner.Builder(signers).setMinSdkVersion(1);
            FileInfo first = sign(@in, apkSignerBuilder);
            FileInfo second = sign(@in, apkSignerBuilder);

            assertFileContentsEqual(first, second);
        }

        [TestMethod]
        public void testEcSignedVerifies()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(EC_P256_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            String @in = "original.apk";

            // NOTE: EC APK signatures are not supported prior to API Level 18
            // Sign so that the APK is guaranteed to verify on API Level 18+
            FileInfo @out = sign(@in, new ApkSigner.Builder(signers).setMinSdkVersion(18));
            assertVerified(verifyForMinSdkVersion(@out, 18));
            // Does not verify on API Level 17 because EC not supported
            assertVerificationFailure(
                verifyForMinSdkVersion(@out, 17), ApkVerifier.Issue.JAR_SIG_UNSUPPORTED_SIG_ALG);
        }

        [TestMethod]
        public void testV1SigningRejectsInvalidZipEntryNames()
        {
            // ZIP/JAR entry name cannot contain CR, LF, or NUL characters when the APK is being
            // JAR-signed.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };


            assertThrows<ApkFormatException>(() =>
                sign(
                    "v1-only-with-cr-in-entry-name.apk",
                    new ApkSigner.Builder(signers).setV1SigningEnabled(true)));
            assertThrows<ApkFormatException>(
                () =>
                    sign(
                        "v1-only-with-lf-in-entry-name.apk",
                        new ApkSigner.Builder(signers).setV1SigningEnabled(true)));
            assertThrows<ApkFormatException>(
                () =>
                    sign(
                        "v1-only-with-nul-in-entry-name.apk",
                        new ApkSigner.Builder(signers).setV1SigningEnabled(true)));
        }

        [TestMethod]
        public void testWeirdZipCompressionMethod()
        {
            // Any ZIP compression method other than STORED is treated as DEFLATED by Android.
            // This APK declares compression method 21 (neither STORED nor DEFLATED) for CERT.RSA entry,
            // but the entry is actually Deflate-compressed.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            sign("weird-compression-method.apk", new ApkSigner.Builder(signers));
        }

        [TestMethod]
        public void testZipCompressionMethodMismatchBetweenLfhAndCd()
        {
            // Android Package Manager ignores compressionMethod field @in Local FileInfo Header and always
            // uses the compressionMethod from Central Directory instead.
            // In this APK, compression method of CERT.RSA is declared as STORED @in Local FileInfo Header
            // and as DEFLATED @in Central Directory. The entry is actually Deflate-compressed.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            sign("mismatched-compression-method.apk", new ApkSigner.Builder(signers));
        }

        [TestMethod]
        public void testDebuggableApk()
        {
            // APK which uses a bool value "true" @in its android:debuggable
            String debuggableBooleanApk = "debuggable-boolean.apk";
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            // Signing debuggable APKs is permitted by default
            sign(debuggableBooleanApk, new ApkSigner.Builder(signers));
            // Signing debuggable APK succeeds when explicitly requested
            sign(debuggableBooleanApk, new ApkSigner.Builder(signers).setDebuggableApkPermitted(true));

            // Signing debuggable APK fails when requested
            assertThrows<CryptographicException>(
                () =>
                    sign(
                        debuggableBooleanApk,
                        new ApkSigner.Builder(signers).setDebuggableApkPermitted(false)));

            // APK which uses a reference value, pointing to bool "false", @in its android:debuggable
            String debuggableResourceApk =
                "debuggable-resource.apk";
            // When we permit signing regardless of whether the APK is debuggable, the value of
            // android:debuggable should be ignored.
            sign(debuggableResourceApk, new ApkSigner.Builder(signers).setDebuggableApkPermitted(true));

            // When we disallow signing debuggable APKs, APKs with android:debuggable being a resource
            // reference must be rejected, because there's no easy way to establish whether the resolved
            // bool value is the same for all resource configurations.
            assertThrows<CryptographicException>(
                () =>
                    sign(
                        debuggableResourceApk,
                        new ApkSigner.Builder(signers).setDebuggableApkPermitted(false)));
        }

        [TestMethod]
        public void testV3SigningWithSignersNotInLineageFails()
        {
            // APKs signed with the v3 scheme after a key rotation must specify the lineage containing
            // the proof of rotation. This test verifies that the signing will fail if the provided
            // signers are not @in the specified lineage.
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME),
                    getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME)
                };

            SigningCertificateLineage lineage =
                Resources.toSigningCertificateLineage("rsa-1024-lineage-2-signers");

            assertThrows<InvalidOperationException>(
                () =>
                    sign(
                        "original.apk",
                        new ApkSigner.Builder(signers)
                            .setSigningCertificateLineage(lineage)));
        }

        [TestMethod]
        public void testSigningWithLineageRequiresOldestSignerForV1AndV2()
        {
            // After a key rotation the oldest signer must still be specified for v1 and v2 signing.
            // The lineage contains the proof of rotation and will be used to determine the oldest
            // signer.
            ApkSigner.SignerConfig firstSigner =
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            ApkSigner.SignerConfig secondSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            ApkSigner.SignerConfig thirdSigner =
                getDefaultSignerConfigFromResources(THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage lineage =
                Resources.toSigningCertificateLineage("rsa-2048-lineage-3-signers");

            // Verifies that the v1 signing scheme requires the oldest signer after a key rotation.
            List<ApkSigner.SignerConfig> signers = new List<ApkSigner.SignerConfig>
            {
                thirdSigner
            };
            try
            {
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signers)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
                fail(
                    "The signing should have failed due to the oldest signer @in the lineage not"
                    + " being provided for v1 signing");
            }
            catch (ArgumentException expected)
            {
            }

            // Verifies that the v2 signing scheme requires the oldest signer after a key rotation.
            try
            {
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signers)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
                fail(
                    "The signing should have failed due to the oldest signer @in the lineage not"
                    + " being provided for v2 signing");
            }
            catch (ArgumentException expected)
            {
            }

            // Verifies that when only the v3 signing scheme is requested the oldest signer does not
            // need to be provided.
            sign(
                "original.apk",
                new ApkSigner.Builder(signers)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));

            // Verifies that an intermediate signer @in the lineage is not sufficient to satisfy the
            // requirement that the oldest signer be provided for v1 and v2 signing.
            signers = new List<ApkSigner.SignerConfig>
            {
                secondSigner,
                thirdSigner
            };
            try
            {
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signers)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
                fail(
                    "The signing should have failed due to the oldest signer @in the lineage not"
                    + " being provided for v1/v2 signing");
            }
            catch (ArgumentException expected)
            {
            }

            // Verifies that the signing is successful when the oldest and newest signers are provided
            // and that intermediate signers are not required.
            signers = new List<ApkSigner.SignerConfig>
            {
                firstSigner, thirdSigner
            };
            sign(
                "original.apk",
                new ApkSigner.Builder(signers)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setSigningCertificateLineage(lineage));
        }

        [TestMethod]
        public void testV3SigningWithMultipleSignersAndNoLineageFails()
        {
            // The v3 signing scheme does not support multiple signers; if multiple signers are provided
            // it is assumed these signers are part of the lineage. This test verifies v3 signing
            // fails if multiple signers are provided without a lineage.
            ApkSigner.SignerConfig firstSigner =
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            ApkSigner.SignerConfig secondSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers = new List<ApkSigner.SignerConfig>
            {
                firstSigner, secondSigner
            };
            assertThrows<InvalidOperationException>(
                () =>
                    sign(
                        "original.apk",
                        new ApkSigner.Builder(signers)
                            .setV1SigningEnabled(true)
                            .setV2SigningEnabled(true)
                            .setV3SigningEnabled(true)));
        }

        [TestMethod]
        public void testLineageCanBeReadAfterV3Signing()
        {
            SigningCertificateLineage.SignerConfig firstSigner =
                Resources.toLineageSignerConfig(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage.SignerConfig secondSigner =
                Resources.toLineageSignerConfig(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage lineage =
                new SigningCertificateLineage.Builder(firstSigner, secondSigner).build();
            ApkSigner.SignerConfig item1 = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            ApkSigner.SignerConfig item2 = getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signerConfigs =
                new List<ApkSigner.SignerConfig>
                {
                    item1,
                    item2
                };
            FileInfo @out =
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signerConfigs)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
            SigningCertificateLineage lineageFromApk = SigningCertificateLineage.readFromApkFile(@out);
            assertTrue(
                "The first signer was not @in the lineage from the signed APK",
                lineageFromApk.isSignerInLineage((firstSigner)));
            assertTrue(
                "The second signer was not @in the lineage from the signed APK",
                lineageFromApk.isSignerInLineage((secondSigner)));
        }

        [TestMethod]
        public void testPublicKeyHasPositiveModulusAfterSigning()
        {
            // The V2 and V3 signature schemes include the public key from the certificate @in the
            // signing block. If a certificate with an RSAPublicKey is improperly encoded with a
            // negative modulus this was previously written to the signing block as is and failed on
            // device verification since on device the public key @in the certificate was reencoded with
            // the correct encoding for the modulus. This test uses an improperly encoded certificate to
            // sign an APK and verifies that the public key @in the signing block is corrected with a
            // positive modulus to allow on device installs / updates.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(
                FIRST_RSA_2048_SIGNER_RESOURCE_NAME,
                FIRST_RSA_2048_SIGNER_CERT_WITH_NEGATIVE_MODULUS);
            List<ApkSigner.SignerConfig> signersList =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            FileInfo signedApk =
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signersList)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
            RSAPublicKey v2PublicKey =
                getRSAPublicKeyFromSigningBlock(
                    signedApk, ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2);
            assertTrue(
                "The modulus @in the public key @in the V2 signing block must not be negative",
                v2PublicKey.modulus.CompareTo(BigInteger.Zero) > 0);
            RSAPublicKey v3PublicKey =
                getRSAPublicKeyFromSigningBlock(
                    signedApk, ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
            assertTrue(
                "The modulus @in the public key @in the V3 signing block must not be negative",
                v3PublicKey.modulus.CompareTo(BigInteger.Zero) > 0);
        }

        [TestMethod]
        public void testV4State_disableV2V3EnableV4_fails()
        {
            ApkSigner.SignerConfig signer =
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);

            assertThrows<InvalidOperationException>(
                () =>
                    sign(
                        "original.apk",
                        new ApkSigner.Builder(new List<ApkSigner.SignerConfig>
                            {
                                signer
                            })
                            .setV1SigningEnabled(true)
                            .setV2SigningEnabled(false)
                            .setV3SigningEnabled(false)
                            .setV4SigningEnabled(true)));
        }

        [TestMethod]
        public void testSignApk_stampFile()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            var messageDigest = SHA256.Create();
            byte[] expectedStampCertificateDigest =
                messageDigest.ComputeHash(sourceStampSigner.getCertificates()[0].getEncoded());

            FileInfo signedApkFile =
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signers)
                        .setV1SigningEnabled(true)
                        .setSourceStampSignerConfig(sourceStampSigner));

            using (RandomAccessFile f = new RandomAccessFile(signedApkFile, "r"))
            {
                DataSource signedApk = DataSources.asDataSource(f, 0, f.length());

                ZipSections zipSections = ApkUtils.findZipSections(signedApk);
                List<CentralDirectoryRecord> cdRecords =
                    V1SchemeVerifier.parseZipCentralDirectory(signedApk, zipSections);
                CentralDirectoryRecord stampCdRecord = null;
                foreach (CentralDirectoryRecord cdRecord in cdRecords)
                {
                    if (ApkUtils.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME.Equals(cdRecord.getName()))
                    {
                        stampCdRecord = cdRecord;
                        break;
                    }
                }

                assertNotNull(stampCdRecord);
                byte[] actualStampCertificateDigest =
                    LocalFileRecord.getUncompressedData(
                        signedApk, stampCdRecord, zipSections.getZipCentralDirectoryOffset());
                assertArrayEquals(expectedStampCertificateDigest, actualStampCertificateDigest);
            }
        }

        [TestMethod]
        public void testSignApk_existingStampFile_sameSourceStamp()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);

            FileInfo signedApk =
                sign(
                    "original-with-stamp-file.apk",
                    new ApkSigner.Builder(signers)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSourceStampSignerConfig(sourceStampSigner));

            ApkVerifier.Result sourceStampVerificationResult =
                verify(signedApk, /* minSdkVersionOverride= */ null);
            assertSourceStampVerified(signedApk, sourceStampVerificationResult);
        }

        [TestMethod]
        public void testSignApk_existingStampFile_differentSourceStamp()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

            var exception =
                assertThrows<ApkFormatException>(
                    () =>
                        sign(
                            "original-with-stamp-file.apk",
                            new ApkSigner.Builder(signers)
                                .setV1SigningEnabled(true)
                                .setV2SigningEnabled(true)
                                .setV3SigningEnabled(true)
                                .setSourceStampSignerConfig(sourceStampSigner)));
            assertEquals(
                String.Format(
                    "Cannot generate SourceStamp. APK contains an existing entry with the"
                    + " name: {0}, and it is different than the provided source stamp"
                    + " certificate",
                    ApkUtils.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME),
                exception.Message);
        }

        [TestMethod]
        public void testSignApk_existingStampFile_differentSourceStamp_forceOverwrite()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signers =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

            FileInfo signedApk =
                sign(
                    "original-with-stamp-file.apk",
                    new ApkSigner.Builder(signers)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setForceSourceStampOverwrite(true)
                        .setSourceStampSignerConfig(sourceStampSigner));

            ApkVerifier.Result sourceStampVerificationResult =
                verify(signedApk, /* minSdkVersionOverride= */ null);
            assertSourceStampVerified(signedApk, sourceStampVerificationResult);
        }

        [TestMethod]
        public void testSignApk_stampBlock_noStampGenerated()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signersList =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };

            FileInfo signedApkFile =
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signersList)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));

            using (RandomAccessFile f = new RandomAccessFile(signedApkFile, "r"))
            {
                DataSource signedApk = DataSources.asDataSource(f, 0, f.length());

                ZipSections zipSections = ApkUtils.findZipSections(signedApk);
                ApkSigningBlockUtils.Result result =
                    new ApkSigningBlockUtils.Result(ApkSigningBlockUtils.VERSION_SOURCE_STAMP);
                assertThrows<ApkSigningBlockUtils.SignatureNotFoundException>(
                    () =>
                        ApkSigningBlockUtils.findSignature(
                            signedApk,
                            zipSections,
                            ApkSigningBlockUtils.VERSION_SOURCE_STAMP,
                            result));
            }
        }

        [TestMethod]
        public void testSignApk_stampBlock_whenV1SignaturePresent()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signersList =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

            FileInfo signedApk =
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signersList)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false)
                        .setSourceStampSignerConfig(sourceStampSigner));

            ApkVerifier.Result sourceStampVerificationResult =
                verify(signedApk, /* minSdkVersionOverride= */ null);
            assertSourceStampVerified(signedApk, sourceStampVerificationResult);
        }

        [TestMethod]
        public void testSignApk_stampBlock_whenV2SignaturePresent()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signersList =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

            FileInfo signedApk =
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signersList)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false)
                        .setSourceStampSignerConfig(sourceStampSigner));

            ApkVerifier.Result sourceStampVerificationResult =
                verifyForMinSdkVersion(signedApk, /* minSdkVersion= */ AndroidSdkVersion.N);
            assertSourceStampVerified(signedApk, sourceStampVerificationResult);
        }

        [TestMethod]
        public void testSignApk_stampBlock_whenV3SignaturePresent()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signersList =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

            FileInfo signedApk =
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signersList)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setSourceStampSignerConfig(sourceStampSigner));

            ApkVerifier.Result sourceStampVerificationResult =
                verifyForMinSdkVersion(signedApk, /* minSdkVersion= */ AndroidSdkVersion.N);
            assertSourceStampVerified(signedApk, sourceStampVerificationResult);
        }

        [TestMethod]
        public void testSignApk_stampBlock_withStampLineage()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> signersList =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
            SigningCertificateLineage sourceStampLineage =
                Resources.toSigningCertificateLineage(
                    LINEAGE_RSA_2048_2_SIGNERS_RESOURCE_NAME);

            FileInfo signedApk =
                sign(
                    "original.apk",
                    new ApkSigner.Builder(signersList)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSourceStampSignerConfig(sourceStampSigner)
                        .setSourceStampSigningCertificateLineage(sourceStampLineage));

            ApkVerifier.Result sourceStampVerificationResult =
                verify(signedApk, /* minSdkVersion= */ null);
            assertSourceStampVerified(signedApk, sourceStampVerificationResult);
        }

        [TestMethod]
        public void testSignApk_Pinlist()
        {
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> rsa2048SignerConfig =
                new List<ApkSigner.SignerConfig>
                {
                    item
                };
            assertGolden(
                "pinsapp-unsigned.apk",
                "golden-pinsapp-signed.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setVerityEnabled(true));
            assertTrue("pinlist.meta file must be @in the signed APK.",
                resourceZipFileContains("golden-pinsapp-signed.apk", "pinlist.meta"));
        }

        [TestMethod]
        public void testOtherSignersSignaturesPreserved_extraSigBlock_signatureAppended()
        {
            // The DefaultApkSignerEngine contains support to append a signature to an existing
            // signing block; any existing signature blocks within the APK signing block should be
            // left intact except for the original verity padding block (since this is regenerated) and
            // the source stamp. This test verifies that an extra signature block is still @in
            // the APK signing block after appending a V2 signature.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(EC_P256_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> ecP256SignerConfig = new List<ApkSigner.SignerConfig>
            {
                item
            };

            FileInfo signedApk = sign("v2-rsa-2048-with-extra-sig-block.apk",
                new ApkSigner.Builder(ecP256SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false)
                    .setOtherSignersSignaturesPreserved(true));

            ApkVerifier.Result result = verify(signedApk, null);
            assertVerified(result);
            assertResultContainsSigners(result, FIRST_RSA_2048_SIGNER_RESOURCE_NAME,
                EC_P256_SIGNER_RESOURCE_NAME);
            assertSigningBlockContains(signedApk, Tuple.Create(EXTRA_BLOCK_VALUE, EXTRA_BLOCK_ID));
        }

        [TestMethod]
        public void testOtherSignersSignaturesPreserved_v1Only_signatureAppended()
        {
            // This test verifies appending an additional V1 signature to an existing V1 signer behaves
            // similar to jarsigner where the APK is then verified as signed by both signers.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(EC_P256_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> ecP256SignerConfig = new List<ApkSigner.SignerConfig>
            {
                item
            };

            FileInfo signedApk = sign("v1-only-with-rsa-2048.apk",
                new ApkSigner.Builder(ecP256SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false)
                    .setOtherSignersSignaturesPreserved(true));

            ApkVerifier.Result result = verify(signedApk, null);
            assertVerified(result);
            assertResultContainsSigners(result, FIRST_RSA_2048_SIGNER_RESOURCE_NAME,
                EC_P256_SIGNER_RESOURCE_NAME);
        }

        [TestMethod]
        public void testOtherSignersSignaturesPreserved_v3OnlyDifferentSigner_throwsException()
        {
            // The V3 Signature Scheme only supports a single signer; if an attempt is made to append
            // a different signer to a V3 signature then an exception should be thrown.
            // The APK used for this test is signed with the ec-p256 signer so use the rsa-2048 to
            // attempt to append a different signature.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> rsa2048SignerConfig = new List<ApkSigner.SignerConfig>
            {
                item
            };

            assertThrows<InvalidOperationException>(() =>
                sign("v3-only-with-stamp.apk",
                    new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setV4SigningEnabled(false)
                        .setOtherSignersSignaturesPreserved(true))
            );
        }

        [TestMethod]
        public void testOtherSignersSignaturesPreserved_v2OnlyAppendV2V3SameSigner_signatureAppended()
        {
            // A V2 and V3 signature can be appended to an existing V2 signature if the same signer is
            // used to resign the APK; this could be used @in a case where an APK was previously signed
            // with just the V2 signature scheme along with additional non-APK signing scheme signature
            // blocks and the signer wanted to preserve those existing blocks.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> rsa2048SignerConfig = new List<ApkSigner.SignerConfig>
            {
                item
            };

            FileInfo signedApk = sign("v2-rsa-2048-with-extra-sig-block.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setV4SigningEnabled(false)
                    .setOtherSignersSignaturesPreserved(true));

            ApkVerifier.Result result = verify(signedApk, null);
            assertVerified(result);
            assertResultContainsSigners(result, FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            assertSigningBlockContains(signedApk, Tuple.Create(EXTRA_BLOCK_VALUE, EXTRA_BLOCK_ID));
        }

        [TestMethod]
        public void testOtherSignersSignaturesPreserved_v2OnlyAppendV3SameSigner_throwsException()
        {
            // A V3 only signature cannot be appended to an existing V2 signature, even when using the
            // same signer, since the V2 signature would then not contain the stripping protection for
            // the V3 signature. If the same signer is being used then the signer should be configured
            // to resign using the V2 signature scheme as well as the V3 signature scheme.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> rsa2048SignerConfig = new List<ApkSigner.SignerConfig>
            {
                item
            };

            assertThrows<InvalidOperationException>(() =>
                sign("v2-rsa-2048-with-extra-sig-block.apk",
                    new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setV4SigningEnabled(false)
                        .setOtherSignersSignaturesPreserved(true)));
        }

        [TestMethod]
        public void testOtherSignersSignaturesPreserved_v1v2IndividuallySign_signaturesAppended()
        {
            // One of the primary requirements for appending signatures is when an APK has already
            // released with two signers; with the minimum signature scheme v2 requirement for target
            // SDK version 30+ each signer must be able to append their signature to the existing
            // signature block. This test verifies an APK with appended signatures verifies as expected
            // after a series of appending V1 and V2 signatures.
            ApkSigner.SignerConfig item = getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> rsa2048SignerConfig = new List<ApkSigner.SignerConfig>
            {
                item
            };
            ApkSigner.SignerConfig item1 = getDefaultSignerConfigFromResources(EC_P256_SIGNER_RESOURCE_NAME);
            List<ApkSigner.SignerConfig> ecP256SignerConfig = new List<ApkSigner.SignerConfig>
            {
                item1
            };

            // When two parties are signing an APK the first must sign with both V1 and V2; this will
            // write the stripping-protection attribute to the V1 signature.
            FileInfo signedApk = sign("original.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false));

            // The second party can then append their signature with both the V1 and V2 signature; this
            // will invalidate the V2 signature of the initial signer since the APK itself will be
            // modified with this signers V1 / jar signature.
            signedApk = sign(signedApk,
                new ApkSigner.Builder(ecP256SignerConfig)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false)
                    .setOtherSignersSignaturesPreserved(true));

            // The first party will then need to resign with just the V2 signature after its previous
            // signature was invalidated by the V1 signature of the second signer; however since this
            // signature is appended its previous V2 signature should be removed from the signature
            // block and replaced with this new signature while preserving the V2 signature of the
            // other signer.
            signedApk = sign(signedApk,
                new ApkSigner.Builder(rsa2048SignerConfig)
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false)
                    .setV4SigningEnabled(false)
                    .setOtherSignersSignaturesPreserved(true));

            ApkVerifier.Result result = verify(signedApk, null);
            assertVerified(result);
            assertResultContainsSigners(result, FIRST_RSA_2048_SIGNER_RESOURCE_NAME,
                EC_P256_SIGNER_RESOURCE_NAME);
        }

        /**
 * Asserts the provided {@code signedApk} contains a signature block with the expected
 * {@code byte[]} value and block ID as specified @in the {@code expectedBlock}.
 */
        private static void assertSigningBlockContains(FileInfo signedApk,
            Tuple<byte[], int> expectedBlock)
        {
            using (RandomAccessFile apkFile = new RandomAccessFile(signedApk, "r"))
            {
                ApkUtilsLite.ApkSigningBlock apkSigningBlock = ApkUtils.findApkSigningBlock(
                    DataSources.asDataSource(apkFile));
                List<Tuple<byte[], int>> signatureBlocks =
                    ApkSigningBlockUtils.getApkSignatureBlocks(apkSigningBlock.getContents());
                foreach (Tuple<byte[], int> signatureBlock in
                         signatureBlocks)
                {
                    if (signatureBlock.Item2.Equals(expectedBlock.Item2))
                    {
                        if (signatureBlock.Item1.SequenceEqual(expectedBlock.Item1))
                        {
                            return;
                        }
                    }
                }

                fail(String.Format(
                    "The APK signing block did not contain the expected block with ID {0:x8}",
                    expectedBlock.Item2));
            }
        }

        /**
 * Asserts the provided verification {@code result} contains the expected {@code signers} for
 * each scheme that was used to verify the APK's signature.
 */
        private static void assertResultContainsSigners(ApkVerifier.Result result, params String[] signers)
        {
            // A result must be successfully verified before verifying any of the result's signers.
            assertTrue(result.isVerified());

            List<X509Certificate> expectedSigners = new List<X509Certificate>();
            foreach (String signer in signers)
            {
                ApkSigner.SignerConfig signerConfig = getDefaultSignerConfigFromResources(signer);
                expectedSigners.AddRange(signerConfig.getCertificates());
            }

            if (result.isVerifiedUsingV1Scheme())
            {
                ISet<X509Certificate> v1Signers = new HashSet<X509Certificate>();
                foreach (ApkVerifier.Result.V1SchemeSignerInfo signer in result.getV1SchemeSigners())
                {
                    v1Signers.Add(signer.getCertificate());
                }

                assertEquals(expectedSigners.Count, v1Signers.Count);
                assertTrue("Expected V1 signers: " + getAllSubjectNamesFrom(expectedSigners)
                                                   + ", actual V1 signers: " + getAllSubjectNamesFrom(v1Signers),
                    expectedSigners.All(s => v1Signers.Contains(s)));
            }

            if (result.isVerifiedUsingV2Scheme())
            {
                ISet<X509Certificate> v2Signers = new HashSet<X509Certificate>();
                foreach (ApkVerifier.Result.V2SchemeSignerInfo signer in
                         result.getV2SchemeSigners())
                {
                    v2Signers.Add(signer.getCertificate());
                }

                assertEquals(expectedSigners.Count, v2Signers.Count);
                assertEquals(expectedSigners.Count, v2Signers.Count);
                assertTrue("Expected V2 signers: " + getAllSubjectNamesFrom(expectedSigners)
                                                   + ", actual V2 signers: " + getAllSubjectNamesFrom(v2Signers),
                    expectedSigners.All(s => v2Signers.Contains(s)));
            }

            if (result.isVerifiedUsingV3Scheme())
            {
                ISet<X509Certificate> v3Signers = new HashSet<X509Certificate>();
                foreach (ApkVerifier.Result.V3SchemeSignerInfo signer in
                         result.getV3SchemeSigners())
                {
                    v3Signers.Add(signer.getCertificate());
                }

                assertEquals(expectedSigners.Count, v3Signers.Count);
                assertTrue("Expected V3 signers: " + getAllSubjectNamesFrom(expectedSigners)
                                                   + ", actual V3 signers: " + getAllSubjectNamesFrom(v3Signers),
                    expectedSigners.All(s => v3Signers.Contains(s)));
            }
        }

        /**
 * Returns a comma delimited {@code String} containing all of the Subject Names from the
 * provided {@code certificates}.
 */
        private static String getAllSubjectNamesFrom(IEnumerable<X509Certificate> certificates)
        {
            StringBuilder result = new StringBuilder();
            foreach (X509Certificate certificate in certificates)
            {
                if (result.Length > 0)
                {
                    result.Append(", ");
                }

                result.Append(certificate.getSubjectDN().getName());
            }

            return result.ToString();
        }

        private static bool resourceZipFileContains(String resourceName, String zipEntryName)
        {
            ZipInputStream zip = new ZipInputStream(
                Resources.toInputStream(resourceName));
            while (true)
            {
                ZipEntry entry = zip.GetNextEntry();
                if (entry == null)
                {
                    break;
                }

                if (entry.Name.Equals(zipEntryName))
                {
                    return true;
                }
            }

            return false;
        }

        private RSAPublicKey getRSAPublicKeyFromSigningBlock(FileInfo apk, int signatureVersionId)
        {
            int signatureVersionBlockId;
            switch (signatureVersionId)
            {
                case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2:
                    signatureVersionBlockId = V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID;
                    break;
                case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3:
                    signatureVersionBlockId = V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID;
                    break;
                default:
                    throw new Exception(
                        "Invalid signature version ID specified: " + signatureVersionId);
            }

            SignatureInfo signatureInfo =
                getSignatureInfoFromApk(apk, signatureVersionId, signatureVersionBlockId);
            // FORMAT:
            // * length prefixed sequence of length prefixed signers
            //   * length-prefixed signed data
            //   * V3+ only - minSDK (uint32)
            //   * V3+ only - maxSDK (uint32)
            //   * length-prefixed sequence of length-prefixed signatures:
            //   * length-prefixed bytes: public key (X.509 SubjectPublicKeyInfo, ASN.1 DER encoded)
            ByteBuffer signers =
                ApkSigningBlockUtils.getLengthPrefixedSlice(signatureInfo.signatureBlock);
            ByteBuffer signer = ApkSigningBlockUtils.getLengthPrefixedSlice(signers);
            // Since all the data is read from the signer block the signedData and signatures are
            // discarded.
            ApkSigningBlockUtils.getLengthPrefixedSlice(signer);
            // For V3+ signature version IDs discard the min / max SDKs as well
            if (signatureVersionId >= ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3)
            {
                signer.getInt();
                signer.getInt();
            }

            ApkSigningBlockUtils.getLengthPrefixedSlice(signer);
            ByteBuffer publicKey = ApkSigningBlockUtils.getLengthPrefixedSlice(signer);
            SubjectPublicKeyInfo subjectPublicKeyInfo =
                Asn1BerParser.parse<SubjectPublicKeyInfo>(publicKey);
            ByteBuffer subjectPublicKeyBuffer = subjectPublicKeyInfo.subjectPublicKey;
            // The SubjectPublicKey is stored as a bit string @in the SubjectPublicKeyInfo with the first
            // byte indicating the number of padding bits @in the public key. Read this first byte to
            // allow parsing the rest of the RSAPublicKey as a sequence.
            subjectPublicKeyBuffer.get();
            return Asn1BerParser.parse<RSAPublicKey>(subjectPublicKeyBuffer);
        }

        private static SignatureInfo getSignatureInfoFromApk(
            FileInfo apkFile, int signatureVersionId, int signatureVersionBlockId)
        {
            using (RandomAccessFile f = new RandomAccessFile(apkFile, "r"))
            {
                DataSource apk = DataSources.asDataSource(f, 0, f.length());
                ZipSections zipSections = ApkUtils.findZipSections(apk);
                ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                    signatureVersionId);
                return ApkSigningBlockUtils.findSignature(apk, zipSections, signatureVersionBlockId,
                    result);
            }
        }

        /**
 * Asserts that signing the specified golden input file using the provided signing configuration
 * produces output identical to the specified golden output file.
 */
        private void assertGolden(
            String inResourceName,
            String expectedOutResourceName,
            ApkSigner.Builder apkSignerBuilder)
        {
            // Sign the provided golden input
            FileInfo @out = sign(inResourceName, apkSignerBuilder);
            assertVerified(verify(@out, AndroidSdkVersion.P));

            // Assert that the output is identical to the provided golden output
            if (@out.Length > int.MaxValue)
            {
                throw new ApplicationException("Output too large: " + @out.Length + " bytes");
            }

            byte[] outData = File.ReadAllBytes(@out.FullName);
            ByteBuffer actualOutBuf = ByteBuffer.wrap(outData);

            ByteBuffer expectedOutBuf =
                ByteBuffer.wrap(Resources.toByteArray(expectedOutResourceName));

            bool identical = false;
            if (actualOutBuf.remaining() == expectedOutBuf.remaining())
            {
                while (actualOutBuf.hasRemaining())
                {
                    if (actualOutBuf.get() != expectedOutBuf.get())
                    {
                        break;
                    }
                }

                identical = !actualOutBuf.hasRemaining();
            }

            if (identical)
            {
                return;
            }

            if (KEEP_FAILING_OUTPUT_AS_FILES)
            {
                FileInfo tmp = new FileInfo(Path.GetTempFileName());
                File.Copy(@out.FullName, tmp.FullName);
                fail(tmp + " differs from " + expectedOutResourceName);
            }
            else
            {
                fail("Output differs from " + expectedOutResourceName);
            }
        }

        private FileInfo sign(FileInfo inApkFile, ApkSigner.Builder apkSignerBuilder)
        {
            using (RandomAccessFile apkFile = new RandomAccessFile(inApkFile, "r"))
            {
                DataSource @in = DataSources.asDataSource(apkFile);
                return sign(@in, apkSignerBuilder);
            }
        }

        private FileInfo sign(String inResourceName, ApkSigner.Builder apkSignerBuilder)
        {
            DataSource @in =
                DataSources.asDataSource(
                    ByteBuffer.wrap(Resources.toByteArray(inResourceName)));
            return sign(@in, apkSignerBuilder);
        }

        private FileInfo sign(DataSource @in, ApkSigner.Builder apkSignerBuilder)
        {
            FileInfo outFile = new FileInfo(Path.GetTempFileName());
            apkSignerBuilder.setInputApk(@in).setOutputApk(outFile);

            FileInfo outFileIdSig = new FileInfo(outFile.FullName + ".idsig");
            apkSignerBuilder.setV4SignatureOutputFile(outFileIdSig);
            apkSignerBuilder.setV4ErrorReportingEnabled(true);

            apkSignerBuilder.build().sign();
            return outFile;
        }

        private static ApkVerifier.Result verifyForMinSdkVersion(FileInfo apk, int minSdkVersion)
        {
            return verify(apk, minSdkVersion);
        }

        private static ApkVerifier.Result verify(FileInfo apk, int? minSdkVersionOverride)
        {
            ApkVerifier.Builder builder = new ApkVerifier.Builder(apk);
            if (minSdkVersionOverride != null)
            {
                builder.setMinCheckedPlatformVersion(minSdkVersionOverride.Value);
            }

            FileInfo idSig = new FileInfo(apk.FullName + ".idsig");
            if (idSig.Exists)
            {
                builder.setV4SignatureFile(idSig);
            }

            return builder.build().verify();
        }

        private static void assertVerified(ApkVerifier.Result result)
        {
            ApkVerifierTest.assertVerified(result);
        }

        private static void assertSourceStampVerified(FileInfo signedApk, ApkVerifier.Result result)
        {
            SignatureInfo signatureInfo =
                getSignatureInfoFromApk(
                    signedApk,
                    ApkSigningBlockUtils.VERSION_SOURCE_STAMP,
                    SourceStampConstants.V2_SOURCE_STAMP_BLOCK_ID);
            assertNotNull(signatureInfo.signatureBlock);
            assertTrue(result.isSourceStampVerified());
        }

        private static void assertVerificationFailure(ApkVerifier.Result result, ApkVerifier.Issue expectedIssue)
        {
            ApkVerifierTest.assertVerificationFailure(result, expectedIssue);
        }

        private void assertFileContentsEqual(FileInfo first, FileInfo second)
        {
            assertArrayEquals(File.ReadAllBytes(first.FullName),
                File.ReadAllBytes(second.FullName));
        }

        private static ApkSigner.SignerConfig getDefaultSignerConfigFromResources(
            String keyNameInResources)
        {
            return getDefaultSignerConfigFromResources(keyNameInResources, false);
        }

        private static ApkSigner.SignerConfig getDefaultSignerConfigFromResources(
            String keyNameInResources, bool deterministicDsaSigning)
        {
            PrivateKey privateKey =
                Resources.toPrivateKey(keyNameInResources + ".pk8");
            List<X509Certificate> certs =
                Resources.toCertificateChain(keyNameInResources + ".x509.pem");
            return new ApkSigner.SignerConfig.Builder(keyNameInResources, privateKey, certs,
                deterministicDsaSigning).build();
        }

        private static ApkSigner.SignerConfig getDefaultSignerConfigFromResources(
            String keyNameInResources, String certNameInResources)
        {
            PrivateKey privateKey =
                Resources.toPrivateKey(keyNameInResources + ".pk8");
            List<X509Certificate> certs =
                Resources.toCertificateChain(certNameInResources);
            return new ApkSigner.SignerConfig.Builder(keyNameInResources, privateKey, certs).build();
        }

        private static ApkSigner.SignerConfig getDeterministicDsaSignerConfigFromResources(
            String keyNameInResources)
        {
            return getDefaultSignerConfigFromResources(keyNameInResources, true);
        }
    }
}