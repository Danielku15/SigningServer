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

namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    /// <summary>
    /// Data sink which stores all received data into the associated {@link ByteBuffer}.
    /// </summary>
    public class ByteBufferSink: SigningServer.Android.Com.Android.Apksig.Util.DataSink
    {
        internal readonly SigningServer.Android.IO.ByteBuffer mBuffer;
        
        public ByteBufferSink(SigningServer.Android.IO.ByteBuffer buffer)
        {
            mBuffer = buffer;
        }
        
        public virtual SigningServer.Android.IO.ByteBuffer GetBuffer()
        {
            return mBuffer;
        }
        
        public void Consume(byte[] buf, int offset, int length)
        {
            try
            {
                mBuffer.Put(buf, offset, length);
            }
            catch (SigningServer.Android.IO.BufferOverflowException e)
            {
                throw new global::System.IO.IOException("Insufficient space in output buffer for " + length + " bytes", e);
            }
        }
        
        public void Consume(SigningServer.Android.IO.ByteBuffer buf)
        {
            int length = buf.Remaining();
            try
            {
                mBuffer.Put(buf);
            }
            catch (SigningServer.Android.IO.BufferOverflowException e)
            {
                throw new global::System.IO.IOException("Insufficient space in output buffer for " + length + " bytes", e);
            }
        }
        
    }
    
}
