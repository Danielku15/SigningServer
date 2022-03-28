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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using SigningServer.Android.Apk;
using SigningServer.Android.Crypto;
using SigningServer.Android.Util;
using SigningServer.Android.Zip;

namespace SigningServer.Android
{
    /// <summary>
    /// APK signer.
    /// The signer preserves as much of the input APK as possible. For example, it preserves the
    /// order of APK entries and preserves their contents, including compressed form and alignment of
    /// data.
    /// </summary>
    internal class ApkSigner
    {
        public const string V1ManifestEntryName = V1SchemeSigner.ManifestEntryName;

        private const int DefaultMinSdkVersion = 21;
        private const short AlignmentZipExtraDataFieldHeaderId = unchecked((short)0xd935);
        private const short AlignmentZipExtraDataFieldMinSizeBytes = 6;


        private readonly X509Certificate2 _certificate;
        private readonly string _inputFile;
        private readonly string _outputFile;

        public bool V1SigningEnabled { get; set; }
        public bool V2SigningEnabled { get; set; }
        public DigestAlgorithm DigestAlgorithm { get; set; }

        public ApkSigner(X509Certificate2 certificate, string inputFile, string outputFile)
        {
            _certificate = certificate;
            _inputFile = inputFile;
            _outputFile = outputFile;
            V1SigningEnabled = true;
            V2SigningEnabled = true;
        }

        /// <summary>
        /// Signs the input APK and outputs the resulting signed APK. The input APK is not modified.
        /// </summary>
        public void Sign()
        {
            // Step 1. Find input APK's main ZIP sections
            using (var inputApk = new DataSource(File.OpenRead(_inputFile)))
            using (var outputApk = new FileStream(_outputFile, FileMode.Create, FileAccess.ReadWrite))
            {
                ApkUtils.ZipSections inputZipSections;
                try
                {
                    inputZipSections = ApkUtils.FindZipSections(inputApk);
                }
                catch (ZipFormatException e)
                {
                    throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
                }

                long inputApkSigningBlockOffset = -1;
                DataSource inputApkSigningBlock = null;

                var apkSigningBlockAndOffset = V2SchemeVerifier.FindApkSigningBlock(inputApk, inputZipSections);
                if (apkSigningBlockAndOffset != null)
                {
                    inputApkSigningBlock = apkSigningBlockAndOffset.Item1;
                    inputApkSigningBlockOffset = apkSigningBlockAndOffset.Item2;
                }

                var inputApkLfhSection = inputApk.Slice(0,
                        (inputApkSigningBlockOffset != -1)
                            ? inputApkSigningBlockOffset
                            : inputZipSections.CentralDirectoryOffset);

                // Step 2. Parse the input APK's ZIP Central Directory
                var inputCd = GetZipCentralDirectory(inputApk, inputZipSections);
                var inputCdRecords = ParseZipCentralDirectory(inputCd, inputZipSections);

                // Step 3. Obtain a signer engine instance
                // Construct a signer engine from the provided parameters

                // Need to extract minSdkVersion from the APK's AndroidManifest.xml
                var minSdkVersion = GetMinSdkVersionFromApk(inputCdRecords, inputApkLfhSection);

                var signerEngine = new DefaultApkSignerEngine(_certificate, minSdkVersion, V1SigningEnabled, V2SigningEnabled, DigestAlgorithm);
                // Step 4. Provide the signer engine with the input APK's APK Signing Block (if any)
                if (inputApkSigningBlock != null)
                {
                    signerEngine.InputApkSigningBlock(inputApkSigningBlock);
                }


                // Step 5. Iterate over input APK's entries and output the Local File Header + data of those
                // entries which need to be output. Entries are iterated in the order in which their Local
                // File Header records are stored in the file. This is to achieve better data locality in
                // case Central Directory entries are in the wrong order.
                var inputCdRecordsSortedByLfhOffset = new List<CentralDirectoryRecord>(inputCdRecords);
                inputCdRecordsSortedByLfhOffset.Sort(CentralDirectoryRecord.BY_LOCAL_FILE_HEADER_OFFSET_COMPARATOR);
                var lastModifiedDateForNewEntries = -1;
                var lastModifiedTimeForNewEntries = -1;
                long inputOffset = 0;
                long outputOffset = 0;
                var outputCdRecordsByName = new Dictionary<string, CentralDirectoryRecord>(inputCdRecords.Count);
                foreach (var inputCdRecord in inputCdRecordsSortedByLfhOffset)
                {
                    var entryName = inputCdRecord.Name;
                    var entryInstructions = signerEngine.InputJarEntry(entryName);
                    bool shouldOutput;
                    switch (entryInstructions.OutputPolicy)
                    {
                        case DefaultApkSignerEngine.OutputPolicy.Output:
                            shouldOutput = true;
                            break;
                        case DefaultApkSignerEngine.OutputPolicy.OutputByEngine:
                        case DefaultApkSignerEngine.OutputPolicy.Skip:
                            shouldOutput = false;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(
                                    "Unknown output policy: " + entryInstructions.OutputPolicy);
                    }
                    var inputLocalFileHeaderStartOffset = inputCdRecord.LocalFileHeaderOffset;
                    if (inputLocalFileHeaderStartOffset > inputOffset)
                    {
                        // Unprocessed data in input starting at inputOffset and ending and the start of
                        // this record's LFH. We output this data verbatim because this signer is supposed
                        // to preserve as much of input as possible.
                        var chunkSize = inputLocalFileHeaderStartOffset - inputOffset;
                        inputApkLfhSection.Feed(inputOffset, chunkSize, outputApk);
                        outputOffset += chunkSize;
                        inputOffset = inputLocalFileHeaderStartOffset;
                    }
                    LocalFileRecord inputLocalFileRecord;
                    try
                    {
                        inputLocalFileRecord =
                                LocalFileRecord.GetRecord(
                                        inputApkLfhSection, inputCdRecord, inputApkLfhSection.Length);
                    }
                    catch (ZipFormatException e)
                    {
                        throw new ApkFormatException("Malformed ZIP entry: " + inputCdRecord.Name, e);
                    }
                    inputOffset += inputLocalFileRecord.Size;
                    var inspectEntryRequest =
                            entryInstructions.InspectJarEntryRequest;
                    if (inspectEntryRequest != null)
                    {
                        FulfillInspectInputJarEntryRequest(
                                inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest);
                    }
                    if (shouldOutput)
                    {
                        // Find the max value of last modified, to be used for new entries added by the
                        // signer.
                        var lastModifiedDate = inputCdRecord.LastModificationDate;
                        var lastModifiedTime = inputCdRecord.LastModificationTime;
                        if ((lastModifiedDateForNewEntries == -1)
                                || (lastModifiedDate > lastModifiedDateForNewEntries)
                                || ((lastModifiedDate == lastModifiedDateForNewEntries)
                                        && (lastModifiedTime > lastModifiedTimeForNewEntries)))
                        {
                            lastModifiedDateForNewEntries = lastModifiedDate;
                            lastModifiedTimeForNewEntries = lastModifiedTime;
                        }
                        inspectEntryRequest = signerEngine.OutputJarEntry(entryName);
                        if (inspectEntryRequest != null)
                        {
                            FulfillInspectInputJarEntryRequest(
                                    inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest);
                        }
                        // Output entry's Local File Header + data
                        var outputLocalFileHeaderOffset = outputOffset;
                        var outputLocalFileRecordSize =
                                OutputInputJarEntryLfhRecordPreservingDataAlignment(
                                        inputApkLfhSection,
                                        inputLocalFileRecord,
                                        outputApk,
                                        outputLocalFileHeaderOffset);
                        outputOffset += outputLocalFileRecordSize;
                        // Enqueue entry's Central Directory record for output
                        CentralDirectoryRecord outputCdRecord;
                        if (outputLocalFileHeaderOffset == inputLocalFileRecord.StartOffsetInArchive)
                        {
                            outputCdRecord = inputCdRecord;
                        }
                        else
                        {
                            outputCdRecord =
                                    inputCdRecord.CreateWithModifiedLocalFileHeaderOffset(
                                            outputLocalFileHeaderOffset);
                        }
                        outputCdRecordsByName.Add(entryName, outputCdRecord);
                    }
                }
                var inputLfhSectionSize = inputApkLfhSection.Length;
                if (inputOffset < inputLfhSectionSize)
                {
                    // Unprocessed data in input starting at inputOffset and ending and the end of the input
                    // APK's LFH section. We output this data verbatim because this signer is supposed
                    // to preserve as much of input as possible.
                    var chunkSize = inputLfhSectionSize - inputOffset;
                    inputApkLfhSection.Feed(inputOffset, chunkSize, outputApk);
                    outputOffset += chunkSize;
                    inputOffset = inputLfhSectionSize;
                }

                // Step 6. Sort output APK's Central Directory records in the order in which they should
                // appear in the output
                var outputCdRecords = new List<CentralDirectoryRecord>(inputCdRecords.Count + 10);
                foreach (var inputCdRecord in inputCdRecords)
                {
                    var entryName = inputCdRecord.Name;
                    if (outputCdRecordsByName.TryGetValue(entryName, out var outputCdRecord))
                    {
                        outputCdRecords.Add(outputCdRecord);
                    }
                }

                // Step 7. Generate and output JAR signatures, if necessary. This may output more Local File
                // Header + data entries and add to the list of output Central Directory records.
                var outputJarSignatureRequest = signerEngine.OutputJarEntries();
                if (outputJarSignatureRequest != null)
                {
                    if (lastModifiedDateForNewEntries == -1)
                    {
                        lastModifiedDateForNewEntries = 0x3a21; // Jan 1 2009 (DOS)
                        lastModifiedTimeForNewEntries = 0;
                    }
                    foreach (var entry in outputJarSignatureRequest.AdditionalJarEntries)
                    {
                        var entryName = entry.Name;
                        var uncompressedData = entry.Data;

                        var deflateResult = ZipUtils.Deflate(uncompressedData);
                        var compressedData = deflateResult.Item1;
                        var uncompressedDataCrc32 = deflateResult.Item2;

                        var inspectEntryRequest = signerEngine.OutputJarEntry(entryName);
                        if (inspectEntryRequest != null)
                        {
                            inspectEntryRequest.DataSink.Write(uncompressedData, 0, uncompressedData.Length);
                            inspectEntryRequest.Done();
                        }
                        var localFileHeaderOffset = outputOffset;
                        outputOffset +=
                                LocalFileRecord.OutputRecordWithDeflateCompressedData(
                                        entryName,
                                        lastModifiedTimeForNewEntries,
                                        lastModifiedDateForNewEntries,
                                        compressedData,
                                        uncompressedDataCrc32,
                                        uncompressedData.Length,
                                        outputApk);
                        outputCdRecords.Add(
                                CentralDirectoryRecord.CreateWithDeflateCompressedData(
                                        entryName,
                                        lastModifiedTimeForNewEntries,
                                        lastModifiedDateForNewEntries,
                                        uncompressedDataCrc32,
                                        compressedData.Length,
                                        uncompressedData.Length,
                                        localFileHeaderOffset));
                    }
                    outputJarSignatureRequest.Done();
                }

                // Step 8. Construct output ZIP Central Directory in an in-memory buffer
                long outputCentralDirSizeBytes = 0;
                foreach (var record in outputCdRecords)
                {
                    outputCentralDirSizeBytes += record.Size;
                }

                var outputCentralDir = new MemoryStream((int)outputCentralDirSizeBytes);
                foreach (var record in outputCdRecords)
                {
                    record.CopyTo(outputCentralDir);
                }
                var outputCentralDirStartOffset = outputOffset;
                var outputCentralDirRecordCount = outputCdRecords.Count;

                // Step 9. Construct output ZIP End of Central Directory record in an in-memory buffer
                var outputEocdBytes = EocdRecord.CreateWithModifiedCentralDirectoryInfo(
                    inputZipSections.EndOfCentralDirectory,
                    outputCentralDirRecordCount,
                    outputCentralDir.Length,
                    outputCentralDirStartOffset);
                var outputEocd = new MemoryStream(outputEocdBytes, true);

                // Step 10. Generate and output APK Signature Scheme v2 signatures, if necessary. This may
                // insert an APK Signing Block just before the output's ZIP Central Directory
                var outputApkSigingBlockRequest =
                    signerEngine.OutputZipSections(
                        outputApk,
                        outputCentralDir,
                        outputEocd);

                outputApk.Position = outputCentralDirStartOffset;
                if (outputApkSigingBlockRequest != null)
                {
                    var outputApkSigningBlock = outputApkSigingBlockRequest.ApkSigningBlock;
                    outputApk.Write(outputApkSigningBlock, 0, outputApkSigningBlock.Length);
                    ZipUtils.SetZipEocdCentralDirectoryOffset(
                        outputEocd, outputCentralDirStartOffset + outputApkSigningBlock.Length);
                    outputApkSigingBlockRequest.Done();
                }

                // Step 11. Output ZIP Central Directory and ZIP End of Central Directory
                outputCentralDir.Position = 0;
                outputCentralDir.CopyTo(outputApk);

                outputApk.Write(outputEocdBytes, 0, outputEocdBytes.Length);
                signerEngine.OutputDone();
            }
        }


        private static byte[] GetZipCentralDirectory(DataSource apk, ApkUtils.ZipSections apkSections)
        {
            long cdSizeBytes = apkSections.CentralDirectorySizeBytes;
            if (cdSizeBytes > int.MaxValue)
            {
                throw new ApkFormatException("ZIP Central Directory too large: " + cdSizeBytes);
            }
            long cdOffset = apkSections.CentralDirectoryOffset;
            return apk.GetByteBuffer(cdOffset, cdSizeBytes);
        }

        private static List<CentralDirectoryRecord> ParseZipCentralDirectory(byte[] cd, ApkUtils.ZipSections apkSections)
        {
            long cdOffset = apkSections.CentralDirectoryOffset;
            int expectedCdRecordCount = apkSections.CentralDirectoryRecordCount;
            var cdRecords = new List<CentralDirectoryRecord>(expectedCdRecordCount);
            var entryNames = new HashSet<string>();
            using (var ms = new DataSource(new MemoryStream(cd)))
            {
                for (var i = 0; i < expectedCdRecordCount; i++)
                {
                    CentralDirectoryRecord cdRecord;
                    try
                    {
                        cdRecord = CentralDirectoryRecord.GetRecord(ms);
                    }
                    catch (ZipFormatException e)
                    {
                        throw new ApkFormatException(
                            "Malformed ZIP Central Directory record #" + (i + 1),
                            e);
                    }

                    var entryName = cdRecord.Name;
                    if (!entryNames.Add(entryName))
                    {
                        throw new ApkFormatException(
                            "Multiple ZIP entries with the same name: " + entryName);
                    }

                    cdRecords.Add(cdRecord);
                }

                if (ms.Remaining > 0)
                {
                    throw new ApkFormatException(
                        "Unused space at the end of ZIP Central Directory: " + ms.Remaining
                                                                             + " bytes starting at file offset " +
                                                                             (cdOffset + ms.Position));
                }
            }

            return cdRecords;
        }

        /// <summary>
        /// Returns the minimum Android version (API Level) supported by the provided APK. This is based
        /// the <code>android:minSdkVersion</code>code> attributes of the APK's <code>AndroidManifest.xml</code>.
        /// </summary>
        /// <param name="cdRecords"></param>
        /// <param name="lhfSection"></param>
        /// <returns></returns>
        private static int GetMinSdkVersionFromApk(List<CentralDirectoryRecord> cdRecords, DataSource lhfSection)
        {
            var androidManifest = GetAndroidManifestFromApk(cdRecords, lhfSection);
            if (androidManifest == null)
            {
                return DefaultMinSdkVersion;
            }

            try
            {
                return ApkUtils.GetMinSdkVersionFromBinaryAndroidManifest(androidManifest);
            }
            catch
            {
                return DefaultMinSdkVersion;
            }
        }

        /// <summary>
        /// Returns the contents of the APK's <code>AndroidManifest.xml</code> or <code>null</code> if this entry
        /// is not present in the APK.
        /// </summary>
        /// <param name="cdRecords"></param>
        /// <param name="lhfSection"></param>
        /// <returns></returns>

        private static byte[] GetAndroidManifestFromApk(List<CentralDirectoryRecord> cdRecords, DataSource lhfSection)
        {
            var androidManifestCdRecord = cdRecords.FirstOrDefault(r => r.Name == ApkUtils.AndroidManifestZipEntryName);
            if (androidManifestCdRecord == null)
            {
                return null;
            }
            return LocalFileRecord.GetUncompressedData(lhfSection, androidManifestCdRecord, lhfSection.Length);
        }


        private static void FulfillInspectInputJarEntryRequest(
            DataSource lfhSection,
            LocalFileRecord localFileRecord,
            DefaultApkSignerEngine.IInspectJarEntryRequest inspectEntryRequest)
        {
            try
            {
                localFileRecord.OutputUncompressedData(lfhSection, inspectEntryRequest.DataSink);
            }
            catch (ZipFormatException e)
            {
                throw new ApkFormatException("Malformed ZIP entry: " + localFileRecord.Name, e);
            }
            inspectEntryRequest.Done();
        }


        private static long OutputInputJarEntryLfhRecordPreservingDataAlignment(
            DataSource inputLfhSection,
            LocalFileRecord inputRecord,
            Stream outputLfhSection,
            long outputOffset)
        {
            var inputOffset = inputRecord.StartOffsetInArchive;
            if (inputOffset == outputOffset)
            {
                // This record's data will be aligned same as in the input APK.
                return inputRecord.OutputRecord(inputLfhSection, outputLfhSection);
            }
            var dataAlignmentMultiple = GetInputJarEntryDataAlignmentMultiple(inputRecord);
            if ((dataAlignmentMultiple <= 1)
                || ((inputOffset % dataAlignmentMultiple)
                    == (outputOffset % dataAlignmentMultiple)))
            {
                // This record's data will be aligned same as in the input APK.
                return inputRecord.OutputRecord(inputLfhSection, outputLfhSection);
            }
            var inputDataStartOffset = inputOffset + inputRecord.DataStartOffset;
            if ((inputDataStartOffset % dataAlignmentMultiple) != 0)
            {
                // This record's data is not aligned in the input APK. No need to align it in the
                // output.
                return inputRecord.OutputRecord(inputLfhSection, outputLfhSection);
            }
            // This record's data needs to be re-aligned in the output. This is achieved using the
            // record's extra field.
            var aligningExtra =
                CreateExtraFieldToAlignData(
                    inputRecord.Extra,
                    outputOffset + inputRecord.ExtraFieldStartOffsetInsideRecord,
                    dataAlignmentMultiple);
            return inputRecord.OutputRecordWithModifiedExtra(inputLfhSection, aligningExtra, outputLfhSection);
        }

        private static byte[] CreateExtraFieldToAlignData(byte[] original, long extraStartOffset, int dataAlignmentMultiple)
        {
            if (dataAlignmentMultiple <= 1)
            {
                return original;
            }
            // In the worst case scenario, we'll increase the output size by 6 + dataAlignment - 1.
            var result = new BinaryWriter(new MemoryStream(new byte[original.Length + 5 + dataAlignmentMultiple], true));


            // Step 1. Output all extra fields other than the one which is to do with alignment
            // FORMAT: sequence of fields. Each field consists of:
            //   * uint16 ID
            //   * uint16 size
            //   * 'size' bytes: payload
            using (var reader = new BinaryReader(new MemoryStream(original)))
            {
                while (reader.BaseStream.Remaining() >= 4)
                {
                    var headerId = reader.ReadInt16();
                    int dataSize = reader.ReadUInt16();
                    if (dataSize > (reader.BaseStream.Remaining()))
                    {
                        // Malformed field -- insufficient input remaining
                        break;
                    }

                    if (((headerId == 0) && (dataSize == 0))
                        || (headerId == AlignmentZipExtraDataFieldHeaderId))
                    {
                        // Ignore the field if it has to do with the old APK data alignment method (filling
                        // the extra field with 0x00 bytes) or the new APK data alignment method.
                        reader.BaseStream.Position += dataSize;
                        continue;
                    }

                    // Copy this field (including header) to the output
                    reader.BaseStream.Position -= 4;

                    var buf = new byte[4 + dataSize];
                    reader.Read(buf, 0, buf.Length);
                    result.Write(buf);
                }

                // Step 2. Add alignment field
                // FORMAT:
                //  * uint16 extra header ID
                //  * uint16 extra data size
                //        Payload ('data size' bytes)
                //      * uint16 alignment multiple (in bytes)
                //      * remaining bytes -- padding to achieve alignment of data which starts after the
                //        extra field
                var dataMinStartOffset =
                    extraStartOffset + result.BaseStream.Position
                                     + AlignmentZipExtraDataFieldMinSizeBytes;
                var paddingSizeBytes =
                    (dataAlignmentMultiple - ((int)(dataMinStartOffset % dataAlignmentMultiple)))
                    % dataAlignmentMultiple;
                result.Write(AlignmentZipExtraDataFieldHeaderId);
                result.Write((ushort)(2 + paddingSizeBytes));
                result.Write((ushort)(dataAlignmentMultiple));
                result.BaseStream.Position += paddingSizeBytes;
                return ((MemoryStream)result.BaseStream).ToArray();
            }
        }

        private static int GetInputJarEntryDataAlignmentMultiple(LocalFileRecord entry)
        {
            if (entry.IsDataCompressed)
            {
                // Compressed entries don't need to be aligned
                return 1;
            }
            // Attempt to obtain the alignment multiple from the entry's extra field.
            var extra = entry.Extra;
            if (extra.Length > 0)
            {
                // FORMAT: sequence of fields. Each field consists of:
                //   * uint16 ID
                //   * uint16 size
                //   * 'size' bytes: payload
                using (var reader = new BinaryReader(new MemoryStream(extra)))
                {
                    while ((reader.BaseStream.Remaining()) >= 4)
                    {
                        var headerId = reader.ReadInt16();
                        int dataSize = reader.ReadUInt16();
                        if (dataSize > (reader.BaseStream.Remaining()))
                        {
                            // Malformed field -- insufficient input remaining
                            break;
                        }
                        if (headerId != AlignmentZipExtraDataFieldHeaderId)
                        {
                            // Skip this field
                            reader.BaseStream.Position += dataSize;
                            continue;
                        }
                        // This is APK alignment field.
                        // FORMAT:
                        //  * uint16 alignment multiple (in bytes)
                        //  * remaining bytes -- padding to achieve alignment of data which starts after
                        //    the extra field
                        if (dataSize < 2)
                        {
                            // Malformed
                            break;
                        }

                        return reader.ReadUInt16();
                    }
                }
            }
            // Fall back to filename-based defaults
            return (entry.Name.EndsWith(".so")) ? 4096 : 4;
        }
    }
}
