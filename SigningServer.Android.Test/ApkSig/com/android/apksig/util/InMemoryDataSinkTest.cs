// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Util
{
    /// <summary>
    /// Tests for the {@link DataSink} returned by {@link DataSinks#newInMemoryDataSink()}.
    /// </summary>
    [RunWith(typeof(var))]
    public class InMemoryDataSinkTest: SigningServer.Android.Com.Android.Apksig.Util.DataSinkTestBase<Com.Android.Apksig.Util.ReadableDataSink>
    {
        protected override SigningServer.Android.Com.Android.Apksig.Util.DataSinkTestBase.CloseableWithDataSink<Com.Android.Apksig.Util.ReadableDataSink> CreateDataSink()
        {
            return SigningServer.Android.Com.Android.Apksig.Util.DataSinkTestBase.CloseableWithDataSink.Of(Com.Android.Apksig.Util.DataSinks.NewInMemoryDataSink());
        }
        
        protected override SigningServer.Android.IO.ByteBuffer GetContents(Com.Android.Apksig.Util.ReadableDataSink dataSink)
        {
            if (dataSink.Size() > SigningServer.Android.Core.IntExtensions.MaxValue)
            {
                throw new SigningServer.Android.IO.IOException("Too much data: " + dataSink.Size());
            }
            return dataSink.GetByteBuffer(0, (int)dataSink.Size());
        }
        
    }
    
}
