// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

/*
 * Copyright (C) 2022 Daniel Kuschny (C# port)
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

namespace SigningServer.Android.Com.Android.Apksig.Util
{
    /// <summary>
    /// Utility methods for working with {@link DataSink} abstraction.
    /// </summary>
    public abstract class DataSinks
    {
        internal DataSinks()
        {
        }
        
        /// <summary>
        /// Returns a {@link DataSink} which outputs received data into the provided
        /// {@link OutputStream}.
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Util.DataSink AsDataSink(SigningServer.Android.IO.OutputStream output)
        {
            return new SigningServer.Android.Com.Android.Apksig.Internal.Util.OutputStreamDataSink(output);
        }
        
        /// <summary>
        /// Returns a {@link DataSink} which outputs received data into the provided file, sequentially,
        /// starting at the beginning of the file.
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Util.DataSink AsDataSink(SigningServer.Android.IO.RandomAccessFile file)
        {
            return new SigningServer.Android.Com.Android.Apksig.Internal.Util.RandomAccessFileDataSink(file);
        }
        
        /// <summary>
        /// Returns a {@link DataSink} which forwards data into the provided {@link MessageDigest}
        /// instances via their {@code update} method. Each {@code MessageDigest} instance receives the
        /// same data.
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Util.DataSink AsDataSink(params SigningServer.Android.Security.MessageDigest[] digests)
        {
            return new SigningServer.Android.Com.Android.Apksig.Internal.Util.MessageDigestSink(digests);
        }
        
        /// <summary>
        /// Returns a new in-memory {@link DataSink} which exposes all data consumed so far via the
        /// {@link DataSource} interface.
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Util.ReadableDataSink NewInMemoryDataSink()
        {
            return new SigningServer.Android.Com.Android.Apksig.Internal.Util.ByteArrayDataSink();
        }
        
        /// <summary>
        /// Returns a new in-memory {@link DataSink} which exposes all data consumed so far via the
        /// {@link DataSource} interface.
        /// 
        /// @param initialCapacity initial capacity in bytes
        /// </summary>
        public static SigningServer.Android.Com.Android.Apksig.Util.ReadableDataSink NewInMemoryDataSink(int initialCapacity)
        {
            return new SigningServer.Android.Com.Android.Apksig.Internal.Util.ByteArrayDataSink(initialCapacity);
        }
        
    }
    
}
