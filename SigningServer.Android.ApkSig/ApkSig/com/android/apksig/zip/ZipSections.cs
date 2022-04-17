// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

/*
 * Copyright (C) 2022 Daniel Kuschny (C# port)
 * Copyright (C) 2020 The Android Open Source Project
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

namespace SigningServer.Android.Com.Android.Apksig.Zip
{
    /// <summary>
    /// Base representation of an APK's zip sections containing the central directory's offset, the size
    /// of the central directory in bytes, the number of records in the central directory, the offset
    /// of the end of central directory, and a ByteBuffer containing the end of central directory
    /// contents.
    /// </summary>
    public class ZipSections
    {
        internal readonly long mCentralDirectoryOffset;
        
        internal readonly long mCentralDirectorySizeBytes;
        
        internal readonly int mCentralDirectoryRecordCount;
        
        internal readonly long mEocdOffset;
        
        internal readonly SigningServer.Android.IO.ByteBuffer mEocd;
        
        public ZipSections(long centralDirectoryOffset, long centralDirectorySizeBytes, int centralDirectoryRecordCount, long eocdOffset, SigningServer.Android.IO.ByteBuffer eocd)
        {
            mCentralDirectoryOffset = centralDirectoryOffset;
            mCentralDirectorySizeBytes = centralDirectorySizeBytes;
            mCentralDirectoryRecordCount = centralDirectoryRecordCount;
            mEocdOffset = eocdOffset;
            mEocd = eocd;
        }
        
        /// <summary>
        /// Returns the start offset of the ZIP Central Directory. This value is taken from the
        /// ZIP End of Central Directory record.
        /// </summary>
        public virtual long GetZipCentralDirectoryOffset()
        {
            return mCentralDirectoryOffset;
        }
        
        /// <summary>
        /// Returns the size (in bytes) of the ZIP Central Directory. This value is taken from the
        /// ZIP End of Central Directory record.
        /// </summary>
        public virtual long GetZipCentralDirectorySizeBytes()
        {
            return mCentralDirectorySizeBytes;
        }
        
        /// <summary>
        /// Returns the number of records in the ZIP Central Directory. This value is taken from the
        /// ZIP End of Central Directory record.
        /// </summary>
        public virtual int GetZipCentralDirectoryRecordCount()
        {
            return mCentralDirectoryRecordCount;
        }
        
        /// <summary>
        /// Returns the start offset of the ZIP End of Central Directory record. The record extends
        /// until the very end of the APK.
        /// </summary>
        public virtual long GetZipEndOfCentralDirectoryOffset()
        {
            return mEocdOffset;
        }
        
        /// <summary>
        /// Returns the contents of the ZIP End of Central Directory.
        /// </summary>
        public virtual SigningServer.Android.IO.ByteBuffer GetZipEndOfCentralDirectory()
        {
            return mEocd;
        }
        
    }
    
}
