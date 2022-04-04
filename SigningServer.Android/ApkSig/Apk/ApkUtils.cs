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
using System.Collections.Generic;
using SigningServer.Android.ApkSig.Internal.Apk;
using SigningServer.Android.ApkSig.Internal.Apk.Stamp;
using SigningServer.Android.ApkSig.Internal.Apk.v1;
using SigningServer.Android.ApkSig.Internal.Zip;
using SigningServer.Android.ApkSig.Util;
using SigningServer.Android.ApkSig.Zip;

namespace SigningServer.Android.ApkSig.Apk
{
    /**
     * APK utilities.
     */
    public static class ApkUtils
    {
        /**
         * Name of the Android manifest ZIP entry in APKs.
         */
        public static readonly String ANDROID_MANIFEST_ZIP_ENTRY_NAME = "AndroidManifest.xml";

        /** Name of the SourceStamp certificate hash ZIP entry in APKs. */
        public static readonly String SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME =
            SourceStampConstants.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME;

        /**
         * Finds the main ZIP sections of the provided APK.
         *
         * @throws IOException if an I/O error occurred while reading the APK
         * @throws ZipFormatException if the APK is malformed
         */
        public static ZipSections findZipSections(DataSource apk)
        {
            return ApkUtilsLite.findZipSections(apk);
        }

        /**
         * Sets the offset of the start of the ZIP Central Directory in the APK's ZIP End of Central
         * Directory record.
         *
         * @param zipEndOfCentralDirectory APK's ZIP End of Central Directory record
         * @param offset offset of the ZIP Central Directory relative to the start of the archive. Must
         *        be between {@code 0} and {@code 2^32 - 1} inclusive.
         */
        public static void setZipEocdCentralDirectoryOffset(
            ByteBuffer zipEndOfCentralDirectory, long offset)
        {
            ByteBuffer eocd = zipEndOfCentralDirectory.slice();
            eocd.order(ByteOrder.LITTLE_ENDIAN);
            ZipUtils.setZipEocdCentralDirectoryOffset(eocd, offset);
        }

        /**
     * Returns the APK Signing Block of the provided {@code apk}.
     *
     * @throws ApkFormatException if the APK is not a valid ZIP archive
     * @throws IOException if an I/O error occurs
     * @throws ApkSigningBlockNotFoundException if there is no APK Signing Block in the APK
     *
     * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2
     * </a>
     */
        public static ApkUtilsLite.ApkSigningBlock findApkSigningBlock(DataSource apk)
        {
            ZipSections inputZipSections;
            try
            {
                inputZipSections = ApkUtils.findZipSections(apk);
            }
            catch (ZipFormatException e)
            {
                throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
            }

            return findApkSigningBlock(apk, inputZipSections);
        }

        /**
     * Returns the APK Signing Block of the provided APK.
     *
     * @throws IOException if an I/O error occurs
     * @throws ApkSigningBlockNotFoundException if there is no APK Signing Block in the APK
     *
     * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2
     * </a>
     */
        public static ApkUtilsLite.ApkSigningBlock findApkSigningBlock(DataSource apk, ZipSections zipSections)
        {
            ApkUtilsLite.ApkSigningBlock apkSigningBlock = ApkUtilsLite.findApkSigningBlock(apk,
                zipSections);
            return new ApkUtilsLite.ApkSigningBlock(apkSigningBlock.getStartOffset(), apkSigningBlock.getContents());
        }

        /**
     * Returns the contents of the APK's {@code AndroidManifest.xml}.
     *
     * @throws IOException if an I/O error occurs while reading the APK
     * @throws ApkFormatException if the APK is malformed
     */
        public static ByteBuffer getAndroidManifest(DataSource apk)
        {
            ZipSections zipSections;
            try
            {
                zipSections = findZipSections(apk);
            }
            catch (ZipFormatException e)
            {
                throw new ApkFormatException("Not a valid ZIP archive", e);
            }

            List<CentralDirectoryRecord> cdRecords =
                V1SchemeVerifier.parseZipCentralDirectory(apk, zipSections);
            CentralDirectoryRecord androidManifestCdRecord = null;
            foreach (CentralDirectoryRecord cdRecord in cdRecords)
            {
                if (ANDROID_MANIFEST_ZIP_ENTRY_NAME.Equals(cdRecord.getName()))
                {
                    androidManifestCdRecord = cdRecord;
                    break;
                }
            }

            if (androidManifestCdRecord == null)
            {
                throw new ApkFormatException("Missing " + ANDROID_MANIFEST_ZIP_ENTRY_NAME);
            }

            DataSource lfhSection = apk.slice(0, zipSections.getZipCentralDirectoryOffset());

            try
            {
                return ByteBuffer.wrap(
                    LocalFileRecord.getUncompressedData(
                        lfhSection, androidManifestCdRecord, lfhSection.size()));
            }
            catch (ZipFormatException e)
            {
                throw new ApkFormatException("Failed to read " + ANDROID_MANIFEST_ZIP_ENTRY_NAME, e);
            }
        }

        /**
     * Android resource ID of the {@code android:minSdkVersion} attribute in AndroidManifest.xml.
     */
        private static readonly int MIN_SDK_VERSION_ATTR_ID = 0x0101020c;

        /**
     * Android resource ID of the {@code android:debuggable} attribute in AndroidManifest.xml.
     */
        private static readonly int DEBUGGABLE_ATTR_ID = 0x0101000f;

        /**
     * Android resource ID of the {@code android:targetSandboxVersion} attribute in
     * AndroidManifest.xml.
     */
        private static readonly int TARGET_SANDBOX_VERSION_ATTR_ID = 0x0101054c;

        /**
     * Android resource ID of the {@code android:targetSdkVersion} attribute in
     * AndroidManifest.xml.
     */
        private static readonly int TARGET_SDK_VERSION_ATTR_ID = 0x01010270;

        private static readonly String USES_SDK_ELEMENT_TAG = "uses-sdk";

        /**
     * Android resource ID of the {@code android:versionCode} attribute in AndroidManifest.xml.
     */
        private static readonly int VERSION_CODE_ATTR_ID = 0x0101021b;

        private static readonly String MANIFEST_ELEMENT_TAG = "manifest";

        /**
     * Android resource ID of the {@code android:versionCodeMajor} attribute in AndroidManifest.xml.
     */
        private static readonly int VERSION_CODE_MAJOR_ATTR_ID = 0x01010576;

        /**
     * Returns the lowest Android platform version (API Level) supported by an APK with the
     * provided {@code AndroidManifest.xml}.
     *
     * @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
     *        resource format
     *
     * @throws MinSdkVersionException if an error occurred while determining the API Level
     */
        public static int getMinSdkVersionFromBinaryAndroidManifest(
            ByteBuffer androidManifestContents)
        {
            // IMPLEMENTATION NOTE: Minimum supported Android platform version number is declared using
            // uses-sdk elements which are children of the top-level manifest element. uses-sdk element
            // declares the minimum supported platform version using the android:minSdkVersion attribute
            // whose default value is 1.
            // For each encountered uses-sdk element, the Android runtime checks that its minSdkVersion
            // is not higher than the runtime's API Level and rejects APKs if it is higher. Thus, the
            // effective minSdkVersion value is the maximum over the encountered minSdkVersion values.

            try
            {
                // If no uses-sdk elements are encountered, Android accepts the APK. We treat this
                // scenario as though the minimum supported API Level is 1.
                int result = 1;

                AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifestContents);
                int eventType = parser.getEventType();
                while (eventType != AndroidBinXmlParser.EVENT_END_DOCUMENT)
                {
                    if ((eventType == AndroidBinXmlParser.EVENT_START_ELEMENT)
                        && (parser.getDepth() == 2)
                        && ("uses-sdk".Equals(parser.getName()))
                        && (parser.getNamespace().Length == 0))
                    {
                        // In each uses-sdk element, minSdkVersion defaults to 1
                        int minSdkVersion = 1;
                        for (int i = 0; i < parser.getAttributeCount(); i++)
                        {
                            if (parser.getAttributeNameResourceId(i) == MIN_SDK_VERSION_ATTR_ID)
                            {
                                int valueType = parser.getAttributeValueType(i);
                                switch (valueType)
                                {
                                    case AndroidBinXmlParser.VALUE_TYPE_INT:
                                        minSdkVersion = parser.getAttributeIntValue(i);
                                        break;
                                    case AndroidBinXmlParser.VALUE_TYPE_STRING:
                                        minSdkVersion =
                                            getMinSdkVersionForCodename(
                                                parser.getAttributeStringValue(i));
                                        break;
                                    default:
                                        throw new MinSdkVersionException(
                                            "Unable to determine APK's minimum supported Android"
                                            + ": unsupported value type in "
                                            + ANDROID_MANIFEST_ZIP_ENTRY_NAME + "'s"
                                            + " minSdkVersion"
                                            + ". Only integer values supported.");
                                }

                                break;
                            }
                        }

                        result = Math.Max(result, minSdkVersion);
                    }

                    eventType = parser.next();
                }

                return result;
            }
            catch (AndroidBinXmlParser.XmlParserException e)
            {
                throw new MinSdkVersionException(
                    "Unable to determine APK's minimum supported Android platform version"
                    + ": malformed binary resource: " + ANDROID_MANIFEST_ZIP_ENTRY_NAME,
                    e);
            }
        }

        private static class CodenamesLazyInitializer
        {
            /**
             * List of platform codename (first letter of) to API Level mappings. The list must be
             * sorted by the first letter. For codenames not in the list, the assumption is that the API
             * Level is incremented by one for every increase in the codename's first letter.
             */
            public static readonly Tuple<char, int>[] SORTED_CODENAMES_FIRST_CHAR_TO_API_LEVEL =
                {
                    Tuple.Create('C', 2),
                    Tuple.Create('D', 3),
                    Tuple.Create('E', 4),
                    Tuple.Create('F', 7),
                    Tuple.Create('G', 8),
                    Tuple.Create('H', 10),
                    Tuple.Create('I', 13),
                    Tuple.Create('J', 15),
                    Tuple.Create('K', 18),
                    Tuple.Create('L', 20),
                    Tuple.Create('M', 22),
                    Tuple.Create('N', 23),
                    Tuple.Create('O', 25),
                };

            public static readonly IComparer<Tuple<char, int>> CODENAME_FIRST_CHAR_COMPARATOR =
                new ByFirstComparator();

            private class ByFirstComparator : IComparer<Tuple<char, int>> {
                public int Compare(Tuple<char, int> o1, Tuple<char, int> o2)
                {
                    char c1 = o1.Item1;
                    char c2 = o2.Item1;
                    return c1 - c2;
                }
            }
        }

        /**
     * Returns the API Level corresponding to the provided platform codename.
     *
     * <p>This method is pessimistic. It returns a value one lower than the API Level with which the
     * platform is actually released (e.g., 23 for N which was released as API Level 24). This is
     * because new features which first appear in an API Level are not available in the early days
     * of that platform version's existence, when the platform only has a codename. Moreover, this
     * method currently doesn't differentiate between initial and MR releases, meaning API Level
     * returned for MR releases may be more than one lower than the API Level with which the
     * platform version is actually released.
     *
     * @throws CodenameMinSdkVersionException if the {@code codename} is not supported
     */
        public static int getMinSdkVersionForCodename(String codename)
        {
            char firstChar = codename.Length == 0 ? ' ' : codename[0];
            // Codenames are case-sensitive. Only codenames starting with A-Z are supported for now.
            // We only look at the first letter of the codename as this is the most important letter.
            if ((firstChar >= 'A') && (firstChar <= 'Z'))
            {
                var sortedCodenamesFirstCharToApiLevel =
                    CodenamesLazyInitializer.SORTED_CODENAMES_FIRST_CHAR_TO_API_LEVEL;
                int searchResult =
                    Array.BinarySearch(
                        sortedCodenamesFirstCharToApiLevel,
                        Tuple.Create(firstChar, 0), // second element of the pair is ignored here
                        CodenamesLazyInitializer.CODENAME_FIRST_CHAR_COMPARATOR);
                if (searchResult >= 0)
                {
                    // Exact match -- searchResult is the index of the matching element
                    return sortedCodenamesFirstCharToApiLevel[searchResult].Item2;
                }

                // Not an exact match -- searchResult is negative and is -(insertion index) - 1.
                // The element at insertionIndex - 1 (if present) is smaller than firstChar and the
                // element at insertionIndex (if present) is greater than firstChar.
                int insertionIndex = -1 - searchResult; // insertionIndex is in [0; array length]
                if (insertionIndex == 0)
                {
                    // 'A' or 'B' -- never released to public
                    return 1;
                }
                else
                {
                    // The element at insertionIndex - 1 is the newest older codename.
                    // API Level bumped by at least 1 for every change in the first letter of codename
                    var newestOlderCodenameMapping =
                        sortedCodenamesFirstCharToApiLevel[insertionIndex - 1];
                    char newestOlderCodenameFirstChar = newestOlderCodenameMapping.Item1;
                    int newestOlderCodenameApiLevel = newestOlderCodenameMapping.Item2;
                    return newestOlderCodenameApiLevel + (firstChar - newestOlderCodenameFirstChar);
                }
            }

            throw new CodenameMinSdkVersionException(
                "Unable to determine APK's minimum supported Android platform version"
                + " : Unsupported codename in " + ANDROID_MANIFEST_ZIP_ENTRY_NAME
                + "'s minSdkVersion: \"" + codename + "\"",
                codename);
        }

        /**
     * Returns {@code true} if the APK is debuggable according to its {@code AndroidManifest.xml}.
     * See the {@code android:debuggable} attribute of the {@code application} element.
     *
     * @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
     *        resource format
     *
     * @throws ApkFormatException if the manifest is malformed
     */
        public static bool getDebuggableFromBinaryAndroidManifest(
            ByteBuffer androidManifestContents)
        {
            // IMPLEMENTATION NOTE: Whether the package is debuggable is declared using the first
            // "application" element which is a child of the top-level manifest element. The debuggable
            // attribute of this application element is coerced to a boolean value. If there is no
            // application element or if it doesn't declare the debuggable attribute, the package is
            // considered not debuggable.

            try
            {
                AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifestContents);
                int eventType = parser.getEventType();
                while (eventType != AndroidBinXmlParser.EVENT_END_DOCUMENT)
                {
                    if ((eventType == AndroidBinXmlParser.EVENT_START_ELEMENT)
                        && (parser.getDepth() == 2)
                        && ("application".Equals(parser.getName()))
                        && (parser.getNamespace().Length == 0))
                    {
                        for (int i = 0; i < parser.getAttributeCount(); i++)
                        {
                            if (parser.getAttributeNameResourceId(i) == DEBUGGABLE_ATTR_ID)
                            {
                                int valueType = parser.getAttributeValueType(i);
                                switch (valueType)
                                {
                                    case AndroidBinXmlParser.VALUE_TYPE_BOOLEAN:
                                    case AndroidBinXmlParser.VALUE_TYPE_STRING:
                                    case AndroidBinXmlParser.VALUE_TYPE_INT:
                                        String value = parser.getAttributeStringValue(i);
                                        return ("true".Equals(value))
                                               || ("TRUE".Equals(value))
                                               || ("1".Equals(value));
                                    case AndroidBinXmlParser.VALUE_TYPE_REFERENCE:
                                        // References to resources are not supported on purpose. The
                                        // reason is that the resolved value depends on the resource
                                        // configuration (e.g, MNC/MCC, locale, screen density) used
                                        // at resolution time. As a result, the same APK may appear as
                                        // debuggable in one situation and as non-debuggable in another
                                        // situation. Such APKs may put users at risk.
                                        throw new ApkFormatException(
                                            "Unable to determine whether APK is debuggable"
                                            + ": " + ANDROID_MANIFEST_ZIP_ENTRY_NAME + "'s"
                                            + " android:debuggable attribute references a"
                                            + " resource. References are not supported for"
                                            + " security reasons. Only constant boolean,"
                                            + " string and int values are supported.");
                                    default:
                                        throw new ApkFormatException(
                                            "Unable to determine whether APK is debuggable"
                                            + ": " + ANDROID_MANIFEST_ZIP_ENTRY_NAME + "'s"
                                            + " android:debuggable attribute uses"
                                            + " unsupported value type. Only boolean,"
                                            + " string and int values are supported.");
                                }
                            }
                        }

                        // This application element does not declare the debuggable attribute
                        return false;
                    }

                    eventType = parser.next();
                }

                // No application element found
                return false;
            }
            catch (AndroidBinXmlParser.XmlParserException e)
            {
                throw new ApkFormatException(
                    "Unable to determine whether APK is debuggable: malformed binary resource: "
                    + ANDROID_MANIFEST_ZIP_ENTRY_NAME,
                    e);
            }
        }

        /**
     * Returns the package name of the APK according to its {@code AndroidManifest.xml} or
     * {@code null} if package name is not declared. See the {@code package} attribute of the
     * {@code manifest} element.
     *
     * @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
     *        resource format
     *
     * @throws ApkFormatException if the manifest is malformed
     */
        public static String getPackageNameFromBinaryAndroidManifest(
            ByteBuffer androidManifestContents)
        {
            // IMPLEMENTATION NOTE: Package name is declared as the "package" attribute of the top-level
            // manifest element. Interestingly, as opposed to most other attributes, Android Package
            // Manager looks up this attribute by its name rather than by its resource ID.

            try
            {
                AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifestContents);
                int eventType = parser.getEventType();
                while (eventType != AndroidBinXmlParser.EVENT_END_DOCUMENT)
                {
                    if ((eventType == AndroidBinXmlParser.EVENT_START_ELEMENT)
                        && (parser.getDepth() == 1)
                        && ("manifest".Equals(parser.getName()))
                        && (parser.getNamespace().Length == 0))
                    {
                        for (int i = 0; i < parser.getAttributeCount(); i++)
                        {
                            if ("package".Equals(parser.getAttributeName(i))
                                && (parser.getNamespace().Length == 0))
                            {
                                return parser.getAttributeStringValue(i);
                            }
                        }

                        // No "package" attribute found
                        return null;
                    }

                    eventType = parser.next();
                }

                // No manifest element found
                return null;
            }
            catch (AndroidBinXmlParser.XmlParserException e)
            {
                throw new ApkFormatException(
                    "Unable to determine APK package name: malformed binary resource: "
                    + ANDROID_MANIFEST_ZIP_ENTRY_NAME,
                    e);
            }
        }

        /**
     * Returns the security sandbox version targeted by an APK with the provided
     * {@code AndroidManifest.xml}.
     *
     * <p>If the security sandbox version is not specified in the manifest a default value of 1 is
     * returned.
     *
     * @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
     *                                resource format
     */
        public static int getTargetSandboxVersionFromBinaryAndroidManifest(
            ByteBuffer androidManifestContents)
        {
            try
            {
                return getAttributeValueFromBinaryAndroidManifest(androidManifestContents,
                    MANIFEST_ELEMENT_TAG, TARGET_SANDBOX_VERSION_ATTR_ID);
            }
            catch (ApkFormatException e)
            {
                // An ApkFormatException indicates the target sandbox is not specified in the manifest;
                // return a default value of 1.
                return 1;
            }
        }

        /**
     * Returns the SDK version targeted by an APK with the provided {@code AndroidManifest.xml}.
     *
     * <p>If the targetSdkVersion is not specified the minimumSdkVersion is returned. If neither
     * value is specified then a value of 1 is returned.
     *
     * @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
     *                                resource format
     */
        public static int getTargetSdkVersionFromBinaryAndroidManifest(
            ByteBuffer androidManifestContents)
        {
            // If the targetSdkVersion is not specified then the platform will use the value of the
            // minSdkVersion; if neither is specified then the platform will use a value of 1.
            int minSdkVersion = 1;
            try
            {
                return getAttributeValueFromBinaryAndroidManifest(androidManifestContents,
                    USES_SDK_ELEMENT_TAG, TARGET_SDK_VERSION_ATTR_ID);
            }
            catch (ApkFormatException e)
            {
                // Expected if the APK does not contain a targetSdkVersion attribute or the uses-sdk
                // element is not specified at all.
            }

            androidManifestContents.rewind();
            try
            {
                minSdkVersion = getMinSdkVersionFromBinaryAndroidManifest(androidManifestContents);
            }
            catch (ApkFormatException e)
            {
                // Similar to above, expected if the APK does not contain a minSdkVersion attribute, or
                // the uses-sdk element is not specified at all.
            }

            return minSdkVersion;
        }

        /**
     * Returns the versionCode of the APK according to its {@code AndroidManifest.xml}.
     *
     * <p>If the versionCode is not specified in the {@code AndroidManifest.xml} or is not a valid
     * integer an ApkFormatException is thrown.
     *
     * @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
     *                                resource format
     * @throws ApkFormatException if an error occurred while determining the versionCode, or if the
     *                            versionCode attribute value is not available.
     */
        public static int getVersionCodeFromBinaryAndroidManifest(ByteBuffer androidManifestContents)
        {
            return getAttributeValueFromBinaryAndroidManifest(androidManifestContents,
                MANIFEST_ELEMENT_TAG, VERSION_CODE_ATTR_ID);
        }

        /**
     * Returns the versionCode and versionCodeMajor of the APK according to its {@code
     * AndroidManifest.xml} combined together as a single long value.
     *
     * <p>The versionCodeMajor is placed in the upper 32 bits, and the versionCode is in the lower
     * 32 bits. If the versionCodeMajor is not specified then the versionCode is returned.
     *
     * @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
     *                                resource format
     * @throws ApkFormatException if an error occurred while determining the version, or if the
     *                            versionCode attribute value is not available.
     */
        public static long getLongVersionCodeFromBinaryAndroidManifest(
            ByteBuffer androidManifestContents)
        {
            // If the versionCode is not found then allow the ApkFormatException to be thrown to notify
            // the caller that the versionCode is not available.
            int versionCode = getVersionCodeFromBinaryAndroidManifest(androidManifestContents);
            long versionCodeMajor = 0;
            try
            {
                androidManifestContents.rewind();
                versionCodeMajor = getAttributeValueFromBinaryAndroidManifest(androidManifestContents,
                    MANIFEST_ELEMENT_TAG, VERSION_CODE_MAJOR_ATTR_ID);
            }
            catch (ApkFormatException e)
            {
                // This is expected if the versionCodeMajor has not been defined for the APK; in this
                // case the return value is just the versionCode.
            }

            return (versionCodeMajor << 32) | versionCode;
        }

        /**
     * Returns the integer value of the requested {@code attributeId} in the specified {@code
     * elementName} from the provided {@code androidManifestContents} in binary Android resource
     * format.
     *
     * @throws ApkFormatException if an error occurred while attempting to obtain the attribute, or
     *                            if the requested attribute is not found.
     */
        private static int getAttributeValueFromBinaryAndroidManifest(
            ByteBuffer androidManifestContents, String elementName, int attributeId)
        {
            if (elementName == null)
            {
                throw new ArgumentNullException(nameof(elementName));
            }

            try
            {
                AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifestContents);
                int eventType = parser.getEventType();
                while (eventType != AndroidBinXmlParser.EVENT_END_DOCUMENT)
                {
                    if ((eventType == AndroidBinXmlParser.EVENT_START_ELEMENT)
                        && (elementName.Equals(parser.getName())))
                    {
                        for (int i = 0; i < parser.getAttributeCount(); i++)
                        {
                            if (parser.getAttributeNameResourceId(i) == attributeId)
                            {
                                int valueType = parser.getAttributeValueType(i);
                                switch (valueType)
                                {
                                    case AndroidBinXmlParser.VALUE_TYPE_INT:
                                    case AndroidBinXmlParser.VALUE_TYPE_STRING:
                                        return parser.getAttributeIntValue(i);
                                    default:
                                        throw new ApkFormatException(
                                            "Unsupported value type, " + valueType
                                                                       + ", for attribute " + String.Format("0x{0:X8}",
                                                                           attributeId) + " under element " +
                                                                       elementName);
                                }
                            }
                        }
                    }

                    eventType = parser.next();
                }

                throw new ApkFormatException(
                    "Failed to determine APK's " + elementName + " attribute "
                    + String.Format("0x{0:X8}", attributeId) + " value");
            }
            catch (AndroidBinXmlParser.XmlParserException e)
            {
                throw new ApkFormatException(
                    "Unable to determine value for attribute " + String.Format("0x{0:X8}",
                        attributeId) + " under element " + elementName
                    + "; malformed binary resource: " + ANDROID_MANIFEST_ZIP_ENTRY_NAME, e);
            }
        }

        public static byte[] computeSha256DigestBytes(byte[] data)
        {
            return ApkUtilsLite.computeSha256DigestBytes(data);
        }
    }
}