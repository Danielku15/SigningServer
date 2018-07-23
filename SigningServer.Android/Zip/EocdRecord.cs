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

using System.IO;

namespace SigningServer.Android.Zip
{
    /// <summary>
    /// ZIP End of Central Directory record.
    /// </summary>
    public static class EocdRecord
    {
        private const int CdRecordCountOnDiskOffset = 8;
        private const int CdRecordCountTotalOffset = 10;
        private const int CdSizeOffset = 12;
        private const int CdOffsetOffset = 16;

        public static byte[] CreateWithModifiedCentralDirectoryInfo(
            byte[] original,
            int centralDirectoryRecordCount,
            long centralDirectorySizeBytes,
            long centralDirectoryOffset)
        {
            var ms = new MemoryStream(original.Length);
            var result = new BinaryWriter(ms);
            result.Write(original);

            ms.Position = CdRecordCountOnDiskOffset;
            result.Write((ushort)centralDirectoryRecordCount);
            ms.Position = CdRecordCountTotalOffset;
            result.Write((ushort)centralDirectoryRecordCount);
            ms.Position = CdSizeOffset;
            result.Write((uint)centralDirectorySizeBytes);
            ms.Position = CdOffsetOffset;
            result.Write((uint)centralDirectoryOffset);

            return ms.ToArray();
        }

    }
}