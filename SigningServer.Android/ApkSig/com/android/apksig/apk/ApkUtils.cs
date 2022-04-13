// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Apk
{
    /// <summary>
    /// APK utilities.
    /// </summary>
    public abstract class ApkUtils
    {
        /// <summary>
        /// Name of the Android manifest ZIP entry in APKs.
        /// </summary>
        public static readonly string ANDROID_MANIFEST_ZIP_ENTRY_NAME = "AndroidManifest.xml";
        
        /// <summary>
        /// Name of the SourceStamp certificate hash ZIP entry in APKs.
        /// </summary>
        public static readonly string SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME = SigningServer.Android.Com.Android.Apksig.Internal.Apk.Stamp.SourceStampConstants.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME;
        
        internal ApkUtils()
        {
        }
        
        /// <summary>
        /// Finds the main ZIP sections of the provided APK.
        /// 
        /// @throws IOException if an I/O error occurred while reading the APK
        /// @throws ZipFormatException if the APK is malformed
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ZipSections FindZipSections(SigningServer.Android.Com.Android.Apksig.Util.DataSource apk)
        {
            SigningServer.Android.Com.Android.Apksig.Zip.ZipSections zipSections = SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.FindZipSections(apk);
            return new SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ZipSections(zipSections.GetZipCentralDirectoryOffset(), zipSections.GetZipCentralDirectorySizeBytes(), zipSections.GetZipCentralDirectoryRecordCount(), zipSections.GetZipEndOfCentralDirectoryOffset(), zipSections.GetZipEndOfCentralDirectory());
        }
        
        /// <summary>
        /// Information about the ZIP sections of an APK.
        /// </summary>
        public class ZipSections: SigningServer.Android.Com.Android.Apksig.Zip.ZipSections
        {
            public ZipSections(long centralDirectoryOffset, long centralDirectorySizeBytes, int centralDirectoryRecordCount, long eocdOffset, SigningServer.Android.IO.ByteBuffer eocd)
                : base (centralDirectoryOffset, centralDirectorySizeBytes, centralDirectoryRecordCount, eocdOffset, eocd)
            {
                ;
            }
            
        }
        
        /// <summary>
        /// Sets the offset of the start of the ZIP Central Directory in the APK's ZIP End of Central
        /// Directory record.
        /// 
        /// @param zipEndOfCentralDirectory APK's ZIP End of Central Directory record
        /// @param offset offset of the ZIP Central Directory relative to the start of the archive. Must
        ///        be between {@code 0} and {@code 2^32 - 1} inclusive.
        /// </summary>
        public static void SetZipEocdCentralDirectoryOffset(SigningServer.Android.IO.ByteBuffer zipEndOfCentralDirectory, long offset)
        {
            SigningServer.Android.IO.ByteBuffer eocd = zipEndOfCentralDirectory.Slice();
            eocd.Order(SigningServer.Android.IO.ByteOrder.LITTLE_ENDIAN);
            SigningServer.Android.Com.Android.Apksig.Internal.Zip.ZipUtils.SetZipEocdCentralDirectoryOffset(eocd, offset);
        }
        
        /// <summary>
        /// Returns the APK Signing Block of the provided {@code apk}.
        /// 
        /// @throws ApkFormatException if the APK is not a valid ZIP archive
        /// @throws IOException if an I/O error occurs
        /// @throws ApkSigningBlockNotFoundException if there is no APK Signing Block in the APK
        /// @see &lt;a href="https://source.android.com/security/apksigning/v2.html"&gt;APK Signature Scheme v2
        /// &lt;/a&gt;
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ApkSigningBlock FindApkSigningBlock(SigningServer.Android.Com.Android.Apksig.Util.DataSource apk)
        {
            SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ZipSections inputZipSections;
            try
            {
                inputZipSections = SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.FindZipSections(apk);
            }
            catch (SigningServer.Android.Com.Android.Apksig.Zip.ZipFormatException e)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Malformed APK: not a ZIP archive", e);
            }
            return SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.FindApkSigningBlock(apk, inputZipSections);
        }
        
        /// <summary>
        /// Returns the APK Signing Block of the provided APK.
        /// 
        /// @throws IOException if an I/O error occurs
        /// @throws ApkSigningBlockNotFoundException if there is no APK Signing Block in the APK
        /// @see &lt;a href="https://source.android.com/security/apksigning/v2.html"&gt;APK Signature Scheme v2
        /// &lt;/a&gt;
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ApkSigningBlock FindApkSigningBlock(SigningServer.Android.Com.Android.Apksig.Util.DataSource apk, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ZipSections zipSections)
        {
            SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.ApkSigningBlock apkSigningBlock = SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.FindApkSigningBlock(apk, zipSections);
            return new SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ApkSigningBlock(apkSigningBlock.GetStartOffset(), apkSigningBlock.GetContents());
        }
        
        /// <summary>
        /// Information about the location of the APK Signing Block inside an APK.
        /// </summary>
        public class ApkSigningBlock: SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.ApkSigningBlock
        {
            /// <summary>
            /// Constructs a new {@code ApkSigningBlock}.
            /// 
            /// @param startOffsetInApk start offset (in bytes, relative to start of file) of the APK
            ///        Signing Block inside the APK file
            /// @param contents contents of the APK Signing Block
            /// </summary>
            public ApkSigningBlock(long startOffsetInApk, SigningServer.Android.Com.Android.Apksig.Util.DataSource contents)
                : base (startOffsetInApk, contents)
            {
                ;
            }
            
        }
        
        /// <summary>
        /// Returns the contents of the APK's {@code AndroidManifest.xml}.
        /// 
        /// @throws IOException if an I/O error occurs while reading the APK
        /// @throws ApkFormatException if the APK is malformed
        /// </summary>
        public static SigningServer.Android.IO.ByteBuffer GetAndroidManifest(SigningServer.Android.Com.Android.Apksig.Util.DataSource apk)
        {
            SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ZipSections zipSections;
            try
            {
                zipSections = SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.FindZipSections(apk);
            }
            catch (SigningServer.Android.Com.Android.Apksig.Zip.ZipFormatException e)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Not a valid ZIP archive", e);
            }
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Zip.CentralDirectoryRecord> cdRecords = SigningServer.Android.Com.Android.Apksig.Internal.Apk.V1.V1SchemeVerifier.ParseZipCentralDirectory(apk, zipSections);
            SigningServer.Android.Com.Android.Apksig.Internal.Zip.CentralDirectoryRecord androidManifestCdRecord = null;
            foreach (SigningServer.Android.Com.Android.Apksig.Internal.Zip.CentralDirectoryRecord cdRecord in cdRecords)
            {
                if (SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME.Equals(cdRecord.GetName()))
                {
                    androidManifestCdRecord = cdRecord;
                    break;
                }
            }
            if (androidManifestCdRecord == null)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Missing " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME);
            }
            SigningServer.Android.Com.Android.Apksig.Util.DataSource lfhSection = apk.Slice(0, zipSections.GetZipCentralDirectoryOffset());
            try
            {
                return SigningServer.Android.IO.ByteBuffer.Wrap(SigningServer.Android.Com.Android.Apksig.Internal.Zip.LocalFileRecord.GetUncompressedData(lfhSection, androidManifestCdRecord, lfhSection.Size()));
            }
            catch (SigningServer.Android.Com.Android.Apksig.Zip.ZipFormatException e)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Failed to read " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME, e);
            }
        }
        
        /// <summary>
        /// Android resource ID of the {@code android:minSdkVersion} attribute in AndroidManifest.xml.
        /// </summary>
        internal static readonly int MIN_SDK_VERSION_ATTR_ID = 0x0101020c;
        
        /// <summary>
        /// Android resource ID of the {@code android:debuggable} attribute in AndroidManifest.xml.
        /// </summary>
        internal static readonly int DEBUGGABLE_ATTR_ID = 0x0101000f;
        
        /// <summary>
        /// Android resource ID of the {@code android:targetSandboxVersion} attribute in
        /// AndroidManifest.xml.
        /// </summary>
        internal static readonly int TARGET_SANDBOX_VERSION_ATTR_ID = 0x0101054c;
        
        /// <summary>
        /// Android resource ID of the {@code android:targetSdkVersion} attribute in
        /// AndroidManifest.xml.
        /// </summary>
        internal static readonly int TARGET_SDK_VERSION_ATTR_ID = 0x01010270;
        
        internal static readonly string USES_SDK_ELEMENT_TAG = "uses-sdk";
        
        /// <summary>
        /// Android resource ID of the {@code android:versionCode} attribute in AndroidManifest.xml.
        /// </summary>
        internal static readonly int VERSION_CODE_ATTR_ID = 0x0101021b;
        
        internal static readonly string MANIFEST_ELEMENT_TAG = "manifest";
        
        /// <summary>
        /// Android resource ID of the {@code android:versionCodeMajor} attribute in AndroidManifest.xml.
        /// </summary>
        internal static readonly int VERSION_CODE_MAJOR_ATTR_ID = 0x01010576;
        
        /// <summary>
        /// Returns the lowest Android platform version (API Level) supported by an APK with the
        /// provided {@code AndroidManifest.xml}.
        /// 
        /// @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
        ///        resource format
        /// @throws MinSdkVersionException if an error occurred while determining the API Level
        /// </summary>
        public static int GetMinSdkVersionFromBinaryAndroidManifest(SigningServer.Android.IO.ByteBuffer androidManifestContents)
        {
            try
            {
                int result = 1;
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser parser = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser(androidManifestContents);
                int eventType = parser.GetEventType();
                while (eventType != SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.EVENT_END_DOCUMENT)
                {
                    if ((eventType == SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.EVENT_START_ELEMENT) && (parser.GetDepth() == 2) && ("uses-sdk".Equals(parser.GetName())) && (parser.GetNamespace().IsEmpty()))
                    {
                        int minSdkVersion = 1;
                        for (int i = 0;i < parser.GetAttributeCount();i++)
                        {
                            if (parser.GetAttributeNameResourceId(i) == SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.MIN_SDK_VERSION_ATTR_ID)
                            {
                                int valueType = parser.GetAttributeValueType(i);
                                switch (valueType)
                                {
                                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.VALUE_TYPE_INT:
                                        minSdkVersion = parser.GetAttributeIntValue(i);
                                        break;
                                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.VALUE_TYPE_STRING:
                                        minSdkVersion = SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.GetMinSdkVersionForCodename(parser.GetAttributeStringValue(i));
                                        break;
                                    default:
                                        throw new SigningServer.Android.Com.Android.Apksig.Apk.MinSdkVersionException("Unable to determine APK's minimum supported Android" + ": unsupported value type in " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME + "'s" + " minSdkVersion" + ". Only integer values supported.");
                                }
                                break;
                            }
                        }
                        result = SigningServer.Android.Core.Math.Max(result, minSdkVersion);
                    }
                    eventType = parser.Next();
                }
                return result;
            }
            catch (SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.XmlParserException e)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.MinSdkVersionException("Unable to determine APK's minimum supported Android platform version" + ": malformed binary resource: " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME, e);
            }
        }
        
        internal class CodenamesLazyInitializer
        {
            /// <summary>
            /// List of platform codename (first letter of) to API Level mappings. The list must be
            /// sorted by the first letter. For codenames not in the list, the assumption is that the API
            /// Level is incremented by one for every increase in the codename's first letter.
            /// </summary>
            internal static readonly SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<char?, int?>[] SORTED_CODENAMES_FIRST_CHAR_TO_API_LEVEL = new SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair[]{
                
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('C', 2), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('D', 3), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('E', 4), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('F', 7), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('G', 8), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('H', 10), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('I', 13), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('J', 15), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('K', 18), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('L', 20), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('M', 22), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('N', 23), 
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of('O', 25)}
            ;
            
            internal static readonly System.Collections.Generic.IComparer<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<char?, int?>> CODENAME_FIRST_CHAR_COMPARATOR = new SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.CodenamesLazyInitializer.ByFirstComparator();
            
            internal class ByFirstComparator: System.Collections.Generic.IComparer<SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<char?, int?>>
            {
                public override int Compare(SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<char?, int?> o1, SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<char?, int?> o2)
                {
                    char c1 = o1.GetFirst();
                    char c2 = o2.GetFirst();
                    return c1 - c2;
                }
                
            }
            
        }
        
        /// <summary>
        /// Returns the API Level corresponding to the provided platform codename.
        /// 
        /// &lt;p&gt;This method is pessimistic. It returns a value one lower than the API Level with which the
        /// platform is actually released (e.g., 23 for N which was released as API Level 24). This is
        /// because new features which first appear in an API Level are not available in the early days
        /// of that platform version's existence, when the platform only has a codename. Moreover, this
        /// method currently doesn't differentiate between initial and MR releases, meaning API Level
        /// returned for MR releases may be more than one lower than the API Level with which the
        /// platform version is actually released.
        /// 
        /// @throws CodenameMinSdkVersionException if the {@code codename} is not supported
        /// </summary>
        public static int GetMinSdkVersionForCodename(string codename)
        {
            char firstChar = codename.IsEmpty() ? ' ' : codename.CharAt(0);
            if ((firstChar >= 'A') && (firstChar <= 'Z'))
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<char?, int?>[] sortedCodenamesFirstCharToApiLevel = SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.CodenamesLazyInitializer.SORTED_CODENAMES_FIRST_CHAR_TO_API_LEVEL;
                int searchResult = SigningServer.Android.Collections.Arrays.BinarySearch(sortedCodenamesFirstCharToApiLevel, SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair.Of(firstChar, null), SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.CodenamesLazyInitializer.CODENAME_FIRST_CHAR_COMPARATOR);
                if (searchResult >= 0)
                {
                    return sortedCodenamesFirstCharToApiLevel[searchResult].GetSecond();
                }
                int insertionIndex = -1 - searchResult;
                if (insertionIndex == 0)
                {
                    return 1;
                }
                else 
                {
                    SigningServer.Android.Com.Android.Apksig.Internal.Util.Pair<char?, int?> newestOlderCodenameMapping = sortedCodenamesFirstCharToApiLevel[insertionIndex - 1];
                    char newestOlderCodenameFirstChar = newestOlderCodenameMapping.GetFirst();
                    int newestOlderCodenameApiLevel = newestOlderCodenameMapping.GetSecond();
                    return newestOlderCodenameApiLevel + (firstChar - newestOlderCodenameFirstChar);
                }
            }
            throw new SigningServer.Android.Com.Android.Apksig.Apk.CodenameMinSdkVersionException("Unable to determine APK's minimum supported Android platform version" + " : Unsupported codename in " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME + "'s minSdkVersion: \\" + codename + "\\", codename);
        }
        
        /// <summary>
        /// Returns {@code true} if the APK is debuggable according to its {@code AndroidManifest.xml}.
        /// See the {@code android:debuggable} attribute of the {@code application} element.
        /// 
        /// @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
        ///        resource format
        /// @throws ApkFormatException if the manifest is malformed
        /// </summary>
        public static bool GetDebuggableFromBinaryAndroidManifest(SigningServer.Android.IO.ByteBuffer androidManifestContents)
        {
            try
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser parser = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser(androidManifestContents);
                int eventType = parser.GetEventType();
                while (eventType != SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.EVENT_END_DOCUMENT)
                {
                    if ((eventType == SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.EVENT_START_ELEMENT) && (parser.GetDepth() == 2) && ("application".Equals(parser.GetName())) && (parser.GetNamespace().IsEmpty()))
                    {
                        for (int i = 0;i < parser.GetAttributeCount();i++)
                        {
                            if (parser.GetAttributeNameResourceId(i) == SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.DEBUGGABLE_ATTR_ID)
                            {
                                int valueType = parser.GetAttributeValueType(i);
                                switch (valueType)
                                {
                                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.VALUE_TYPE_BOOLEAN:
                                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.VALUE_TYPE_STRING:
                                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.VALUE_TYPE_INT:
                                        string value = parser.GetAttributeStringValue(i);
                                        return ("true".Equals(value)) || ("TRUE".Equals(value)) || ("1".Equals(value));
                                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.VALUE_TYPE_REFERENCE:
                                        throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Unable to determine whether APK is debuggable" + ": " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME + "'s" + " android:debuggable attribute references a" + " resource. References are not supported for" + " security reasons. Only constant boolean," + " string and int values are supported.");
                                    default:
                                        throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Unable to determine whether APK is debuggable" + ": " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME + "'s" + " android:debuggable attribute uses" + " unsupported value type. Only boolean," + " string and int values are supported.");
                                }
                            }
                        }
                        return false;
                    }
                    eventType = parser.Next();
                }
                return false;
            }
            catch (SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.XmlParserException e)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Unable to determine whether APK is debuggable: malformed binary resource: " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME, e);
            }
        }
        
        /// <summary>
        /// Returns the package name of the APK according to its {@code AndroidManifest.xml} or
        /// {@code null} if package name is not declared. See the {@code package} attribute of the
        /// {@code manifest} element.
        /// 
        /// @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
        ///        resource format
        /// @throws ApkFormatException if the manifest is malformed
        /// </summary>
        public static string GetPackageNameFromBinaryAndroidManifest(SigningServer.Android.IO.ByteBuffer androidManifestContents)
        {
            try
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser parser = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser(androidManifestContents);
                int eventType = parser.GetEventType();
                while (eventType != SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.EVENT_END_DOCUMENT)
                {
                    if ((eventType == SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.EVENT_START_ELEMENT) && (parser.GetDepth() == 1) && ("manifest".Equals(parser.GetName())) && (parser.GetNamespace().IsEmpty()))
                    {
                        for (int i = 0;i < parser.GetAttributeCount();i++)
                        {
                            if ("package".Equals(parser.GetAttributeName(i)) && (parser.GetNamespace().IsEmpty()))
                            {
                                return parser.GetAttributeStringValue(i);
                            }
                        }
                        return null;
                    }
                    eventType = parser.Next();
                }
                return null;
            }
            catch (SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.XmlParserException e)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Unable to determine APK package name: malformed binary resource: " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME, e);
            }
        }
        
        /// <summary>
        /// Returns the security sandbox version targeted by an APK with the provided
        /// {@code AndroidManifest.xml}.
        /// 
        /// &lt;p&gt;If the security sandbox version is not specified in the manifest a default value of 1 is
        /// returned.
        /// 
        /// @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
        ///                                resource format
        /// </summary>
        public static int GetTargetSandboxVersionFromBinaryAndroidManifest(SigningServer.Android.IO.ByteBuffer androidManifestContents)
        {
            try
            {
                return SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.GetAttributeValueFromBinaryAndroidManifest(androidManifestContents, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.MANIFEST_ELEMENT_TAG, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.TARGET_SANDBOX_VERSION_ATTR_ID);
            }
            catch (SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException e)
            {
                return 1;
            }
        }
        
        /// <summary>
        /// Returns the SDK version targeted by an APK with the provided {@code AndroidManifest.xml}.
        /// 
        /// &lt;p&gt;If the targetSdkVersion is not specified the minimumSdkVersion is returned. If neither
        /// value is specified then a value of 1 is returned.
        /// 
        /// @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
        ///                                resource format
        /// </summary>
        public static int GetTargetSdkVersionFromBinaryAndroidManifest(SigningServer.Android.IO.ByteBuffer androidManifestContents)
        {
            int minSdkVersion = 1;
            try
            {
                return SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.GetAttributeValueFromBinaryAndroidManifest(androidManifestContents, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.USES_SDK_ELEMENT_TAG, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.TARGET_SDK_VERSION_ATTR_ID);
            }
            catch (SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException e)
            {
            }
            androidManifestContents.Rewind();
            try
            {
                minSdkVersion = SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.GetMinSdkVersionFromBinaryAndroidManifest(androidManifestContents);
            }
            catch (SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException e)
            {
            }
            return minSdkVersion;
        }
        
        /// <summary>
        /// Returns the versionCode of the APK according to its {@code AndroidManifest.xml}.
        /// 
        /// &lt;p&gt;If the versionCode is not specified in the {@code AndroidManifest.xml} or is not a valid
        /// integer an ApkFormatException is thrown.
        /// 
        /// @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
        ///                                resource format
        /// @throws ApkFormatException if an error occurred while determining the versionCode, or if the
        ///                            versionCode attribute value is not available.
        /// </summary>
        public static int GetVersionCodeFromBinaryAndroidManifest(SigningServer.Android.IO.ByteBuffer androidManifestContents)
        {
            return SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.GetAttributeValueFromBinaryAndroidManifest(androidManifestContents, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.MANIFEST_ELEMENT_TAG, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.VERSION_CODE_ATTR_ID);
        }
        
        /// <summary>
        /// Returns the versionCode and versionCodeMajor of the APK according to its {@code
        /// AndroidManifest.xml} combined together as a single long value.
        /// 
        /// &lt;p&gt;The versionCodeMajor is placed in the upper 32 bits, and the versionCode is in the lower
        /// 32 bits. If the versionCodeMajor is not specified then the versionCode is returned.
        /// 
        /// @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
        ///                                resource format
        /// @throws ApkFormatException if an error occurred while determining the version, or if the
        ///                            versionCode attribute value is not available.
        /// </summary>
        public static long GetLongVersionCodeFromBinaryAndroidManifest(SigningServer.Android.IO.ByteBuffer androidManifestContents)
        {
            int versionCode = SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.GetVersionCodeFromBinaryAndroidManifest(androidManifestContents);
            long versionCodeMajor = 0;
            try
            {
                androidManifestContents.Rewind();
                versionCodeMajor = SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.GetAttributeValueFromBinaryAndroidManifest(androidManifestContents, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.MANIFEST_ELEMENT_TAG, SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.VERSION_CODE_MAJOR_ATTR_ID);
            }
            catch (SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException e)
            {
            }
            return (versionCodeMajor << 32) | versionCode;
        }
        
        /// <summary>
        /// Returns the integer value of the requested {@code attributeId} in the specified {@code
        /// elementName} from the provided {@code androidManifestContents} in binary Android resource
        /// format.
        /// 
        /// @throws ApkFormatException if an error occurred while attempting to obtain the attribute, or
        ///                            if the requested attribute is not found.
        /// </summary>
        internal static int GetAttributeValueFromBinaryAndroidManifest(SigningServer.Android.IO.ByteBuffer androidManifestContents, string elementName, int attributeId)
        {
            if (elementName == null)
            {
                throw new System.NullReferenceException("elementName cannot be null");
            }
            try
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser parser = new SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser(androidManifestContents);
                int eventType = parser.GetEventType();
                while (eventType != SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.EVENT_END_DOCUMENT)
                {
                    if ((eventType == SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.EVENT_START_ELEMENT) && (elementName.Equals(parser.GetName())))
                    {
                        for (int i = 0;i < parser.GetAttributeCount();i++)
                        {
                            if (parser.GetAttributeNameResourceId(i) == attributeId)
                            {
                                int valueType = parser.GetAttributeValueType(i);
                                switch (valueType)
                                {
                                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.VALUE_TYPE_INT:
                                    case SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.VALUE_TYPE_STRING:
                                        return parser.GetAttributeIntValue(i);
                                    default:
                                        throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Unsupported value type, " + valueType + ", for attribute " + SigningServer.Android.Core.StringExtensions.Format("0x%08X", attributeId) + " under element " + elementName);
                                }
                            }
                        }
                    }
                    eventType = parser.Next();
                }
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Failed to determine APK's " + elementName + " attribute " + SigningServer.Android.Core.StringExtensions.Format("0x%08X", attributeId) + " value");
            }
            catch (SigningServer.Android.Com.Android.Apksig.Internal.Apk.AndroidBinXmlParser.XmlParserException e)
            {
                throw new SigningServer.Android.Com.Android.Apksig.Apk.ApkFormatException("Unable to determine value for attribute " + SigningServer.Android.Core.StringExtensions.Format("0x%08X", attributeId) + " under element " + elementName + "; malformed binary resource: " + SigningServer.Android.Com.Android.Apksig.Apk.ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME, e);
            }
        }
        
        public static sbyte[] ComputeSha256DigestBytes(sbyte[] data)
        {
            return SigningServer.Android.Com.Android.Apksig.Apk.ApkUtilsLite.ComputeSha256DigestBytes(data);
        }
        
    }
    
}
