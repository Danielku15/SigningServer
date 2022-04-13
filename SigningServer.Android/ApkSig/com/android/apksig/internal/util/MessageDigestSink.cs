// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Util
{
    /// <summary>
    /// Data sink which feeds all received data into the associated {@link MessageDigest} instances. Each
    /// {@code MessageDigest} instance receives the same data.
    /// </summary>
    public class MessageDigestSink: SigningServer.Android.Com.Android.Apksig.Util.DataSink
    {
        internal readonly SigningServer.Android.Security.MessageDigest[] mMessageDigests;
        
        public MessageDigestSink(SigningServer.Android.Security.MessageDigest[] digests)
        {
            mMessageDigests = digests;
        }
        
        public override void Consume(sbyte[] buf, int offset, int length)
        {
            foreach (SigningServer.Android.Security.MessageDigest md in mMessageDigests)
            {
                md.Update(buf, offset, length);
            }
        }
        
        public override void Consume(SigningServer.Android.IO.ByteBuffer buf)
        {
            int originalPosition = buf.Position();
            foreach (SigningServer.Android.Security.MessageDigest md in mMessageDigests)
            {
                buf.Position(originalPosition);
                md.Update(buf);
            }
        }
        
    }
    
}
