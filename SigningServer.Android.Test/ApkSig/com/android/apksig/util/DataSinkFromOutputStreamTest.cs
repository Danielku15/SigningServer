// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Util
{
    /// <summary>
    /// Tests for the {@link DataSink} returned by {@link DataSinks#asDataSink(java.io.OutputStream)}.
    /// </summary>
    public class DataSinkFromOutputStreamTest: SigningServer.Android.Com.Android.Apksig.Util.DataSinkTestBase<Com.Android.Apksig.Internal.Util.OutputStreamDataSink>
    {
        protected override SigningServer.Android.Com.Android.Apksig.Util.DataSinkTestBase.CloseableWithDataSink<Com.Android.Apksig.Internal.Util.OutputStreamDataSink> CreateDataSink()
        {
            return SigningServer.Android.Com.Android.Apksig.Util.DataSinkTestBase.CloseableWithDataSink.Of<Com.Android.Apksig.Internal.Util.OutputStreamDataSink>((Com.Android.Apksig.Internal.Util.OutputStreamDataSink)Com.Android.Apksig.Util.DataSinks.AsDataSink(new SigningServer.Android.IO.ByteArrayOutputStream()));
        }
        
        protected override SigningServer.Android.IO.ByteBuffer GetContents(Com.Android.Apksig.Internal.Util.OutputStreamDataSink dataSink)
        {
            return SigningServer.Android.IO.ByteBuffer.Wrap(((SigningServer.Android.IO.ByteArrayOutputStream)dataSink.GetOutputStream()).ToByteArray());
        }
        
    }
    
}
