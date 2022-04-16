// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Util
{
    /// <summary>
    /// Consumer of input data which may be provided in one go or in chunks.
    /// </summary>
    public interface DataSink
    {
        /// <summary>
        /// Consumes the provided chunk of data.
        /// 
        /// &lt;p&gt;This data sink guarantees to not hold references to the provided buffer after this method
        /// terminates.
        /// 
        /// @throws IndexOutOfBoundsException if {@code offset} or {@code length} are negative, or if
        ///         {@code offset + length} is greater than {@code buf.length}.
        /// </summary>
        public void Consume(byte[] buf, int offset, int length);
        
        /// <summary>
        /// Consumes all remaining data in the provided buffer and advances the buffer's position
        /// to the buffer's limit.
        /// 
        /// &lt;p&gt;This data sink guarantees to not hold references to the provided buffer after this method
        /// terminates.
        /// </summary>
        public void Consume(SigningServer.Android.IO.ByteBuffer buf);
        
    }
    
}
