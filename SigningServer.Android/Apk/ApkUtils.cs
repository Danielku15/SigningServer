/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2018 Daniel Kuschny (C# port based on oreo-master)
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
using System.Collections;
using System.Collections.Generic;
using SigningServer.Android.Util;
using SigningServer.Android.Zip;

namespace SigningServer.Android.Apk
{
    /// <summary>
    /// APK utilities.
    /// </summary>
    static class ApkUtils
    {
        /// <summary>
        /// Android resource ID of the <code>android:minSdkVersion</code> attribute in AndroidManifest.xml.
        /// </summary>
        private const int MinSdkVersionAttrId = 0x0101020c;


        /// <summary>
        /// Finds the main ZIP sections of the provided APK.
        /// </summary>
        /// <param name="apk"></param>
        /// <returns></returns>
        public static ZipSections FindZipSections(DataSource apk)
        {
            var eocdAndOffsetInFile =
                ZipUtils.FindZipEndOfCentralDirectoryRecord(apk);
            if (eocdAndOffsetInFile == null)
            {
                throw new ZipFormatException("ZIP End of Central Directory record not found");
            }

            var eocdBuf = eocdAndOffsetInFile.Item1;
            var eocdOffset = eocdAndOffsetInFile.Item2;
            var cdStartOffset = ZipUtils.GetZipEocdCentralDirectoryOffset(eocdBuf);
            if (cdStartOffset > eocdOffset)
            {
                throw new ZipFormatException(
                    "ZIP Central Directory start offset out of range: " + cdStartOffset
                                                                        + ". ZIP End of Central Directory offset: " + eocdOffset);
            }
            var cdSizeBytes = ZipUtils.GetZipEocdCentralDirectorySizeBytes(eocdBuf);
            var cdEndOffset = cdStartOffset + cdSizeBytes;
            if (cdEndOffset > eocdOffset)
            {
                throw new ZipFormatException(
                    "ZIP Central Directory overlaps with End of Central Directory"
                    + ". CD end: " + cdEndOffset
                    + ", EoCD start: " + eocdOffset);
            }
            var cdRecordCount = ZipUtils.GetZipEocdCentralDirectoryTotalRecordCount(eocdBuf);
            return new ZipSections(
                cdStartOffset,
                cdSizeBytes,
                cdRecordCount,
                eocdOffset,
                eocdBuf);
        }

        /// <summary>
        /// Returns the lowest Android platform version (API Level) supported by an APK with the
        /// provided  <code>AndroidManifest.xml</code>
        /// </summary>
        /// <param name="androidManifest">contents of <code>AndroidManifest.xml</code> in binary Android resource format</param>
        /// <returns></returns>
        public static int GetMinSdkVersionFromBinaryAndroidManifest(byte[] androidManifest)
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
                AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifest);
                var eventType = parser.EventType;
                while (eventType != AndroidBinXmlParser.EndOfDocument)
                {
                    if ((eventType == AndroidBinXmlParser.EventStartElement)
                            && (parser.Depth == 2)
                            && ("uses-sdk" == parser.Name)
                            && (String.IsNullOrEmpty(parser.Namespace)))
                    {
                        // In each uses-sdk element, minSdkVersion defaults to 1
                        int minSdkVersion = 1;
                        for (int i = 0; i < parser.AttributeCount; i++)
                        {
                            if (parser.GetAttributeNameResourceId(i) == MinSdkVersionAttrId)
                            {
                                int valueType = parser.GetAttributeValueType(i);
                                switch (valueType)
                                {
                                    case AndroidBinXmlParser.ValueTypeInt:
                                        minSdkVersion = parser.GetAttributeIntValue(i);
                                        break;
                                    case AndroidBinXmlParser.ValueTypeString:
                                        minSdkVersion = GetMinSdkVersionForCodename(parser.GetAttributeStringValue(i));
                                        break;
                                    default:
                                        throw new FormatException(
                                                "Unable to determine APK's minimum supported Android"
                                                        + ": unsupported value type in "
                                                        + AndroidManifestZipEntryName + "'s"
                                                        + " minSdkVersion"
                                                        + ". Only integer values supported.");
                                }
                                break;
                            }
                        }
                        result = Math.Max(result, minSdkVersion);
                    }
                    eventType = parser.Next();
                }
                return result;
            }
            catch (Exception e)
            {
                throw new FormatException(
                        "Unable to determine APK's minimum supported Android platform version"
                                + ": malformed binary resource: " + AndroidManifestZipEntryName,
                        e);
            }
        }


        /*
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
        /// <summary>
        /// Returns the API Level corresponding to the provided platform codename.
        /// </summary>
        /// <remarks>
        /// This method is pessimistic. It returns a value one lower than the API Level with which the
        /// platform is actually released(e.g., 23 for N which was released as API Level 24). This is
        /// because new features which first appear in an API Level are not available in the early days
        /// of that platform version's existence, when the platform only has a codename. Moreover, this
        /// method currently doesn't differentiate between initial and MR releases, meaning API Level
        /// returned for MR releases may be more than one lower than the API Level with which the
        /// platform version is actually released.
        /// </remarks>
        /// <param name="codename"></param>
        /// <returns></returns>
        static int GetMinSdkVersionForCodename(string codename)
        {
            char firstChar = string.IsNullOrEmpty(codename) ? ' ' : codename[0];
            // Codenames are case-sensitive. Only codenames starting with A-Z are supported for now.
            // We only look at the first letter of the codename as this is the most important letter.
            if ((firstChar >= 'A') && (firstChar <= 'Z'))
            {
                var sortedCodenamesFirstCharToApiLevel =
                        CodenamesLazyInitializer.SORTED_CODENAMES_FIRST_CHAR_TO_API_LEVEL;
                int searchResult =
                        Array.BinarySearch(
                                sortedCodenamesFirstCharToApiLevel,
                                Tuple.Create(firstChar, -1), // second element of the pair is ignored here
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
                    Tuple<char, int> newestOlderCodenameMapping =
                            sortedCodenamesFirstCharToApiLevel[insertionIndex - 1];
                    char newestOlderCodenameFirstChar = newestOlderCodenameMapping.Item1;
                    int newestOlderCodenameApiLevel = newestOlderCodenameMapping.Item2;
                    return newestOlderCodenameApiLevel + (firstChar - newestOlderCodenameFirstChar);
                }
            }
            throw new FormatException(
                    "Unable to determine APK's minimum supported Android platform version"
                            + " : Unsupported codename in " + AndroidManifestZipEntryName
                            + "'s minSdkVersion: \"" + codename + "\"");
        }

        private static class CodenamesLazyInitializer
        {
            /// <summary>
            /// List of platform codename(first letter of) to API Level mappings.The list must be
            /// sorted by the first letter. For codenames not in the list, the assumption is that the API
            /// Level is incremented by one for every increase in the codename's first letter.
            /// </summary>
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

            public static readonly IComparer CODENAME_FIRST_CHAR_COMPARATOR = new ByFirstComparator();
            private class ByFirstComparator : IComparer, IComparer<Tuple<char, int>>
            {

                public int Compare(object x, object y)
                {
                    return Compare(x as Tuple<char, int>, y as Tuple<char, int>);
                }

                public int Compare(Tuple<char, int> x, Tuple<char, int> y)
                {
                    if (ReferenceEquals(x, y)) return 0;
                    if (ReferenceEquals(null, y)) return 1;
                    if (ReferenceEquals(null, x)) return -1;

                    return x.Item1.CompareTo(y.Item2);
                }
            }
        }


        /// <summary>
        /// Information about the ZIP sections of an APK.
        /// </summary>
        public class ZipSections
        {
            /// <summary>
            /// Returns the start offset of the ZIP Central Directory. This value is taken from the ZIP End of Central Directory record.
            /// </summary>
            public uint CentralDirectoryOffset { get; }

            /// <summary>
            /// Returns the size (in bytes) of the ZIP Central Directory. This value is taken from the ZIP End of Central Directory record.
            /// </summary>
            public uint CentralDirectorySizeBytes { get; }

            /// <summary>
            /// Returns the number of records in the ZIP Central Directory. This value is taken from the ZIP End of Central Directory record.
            /// </summary>
            public ushort CentralDirectoryRecordCount { get; }

            /// <summary>
            /// Returns the start offset of the ZIP End of Central Directory record. The record extends until the very end of the APK.
            /// </summary>
            public long EndOfCentralDirectoryOffset { get; }
            /// <summary>
            /// Returns the contents of the ZIP End of Central Directory.
            /// </summary>
            public byte[] EndOfCentralDirectory { get; }

            public ZipSections(
                uint centralDirectoryOffset,
                uint centralDirectorySizeBytes,
                ushort centralDirectoryRecordCount,
                long endOfCentralDirectoryOffset,
                byte[] endOfCentralDirectory)
            {
                CentralDirectoryOffset = centralDirectoryOffset;
                CentralDirectorySizeBytes = centralDirectorySizeBytes;
                CentralDirectoryRecordCount = centralDirectoryRecordCount;
                EndOfCentralDirectoryOffset = endOfCentralDirectoryOffset;
                EndOfCentralDirectory = endOfCentralDirectory;
            }
        }

        /// <summary>
        /// Name of the Android manifest ZIP entry in APKs.
        /// </summary>
        public const string AndroidManifestZipEntryName = "AndroidManifest.xml";
    }
}
