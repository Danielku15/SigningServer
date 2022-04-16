// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SigningServer.Android.Com.Android.Apksig.Util
{
    /// <summary>
    /// Tests for the {@link DataSource} returned by {@link DataSources#asDataSource(ByteBuffer)}.
    /// </summary>
    [TestClass]
    public class DataSourceFromByteBufferTest: SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase
    {
        [Test]
        public virtual void TestChangesToBufferPosAndLimitNotVisible()
        {
            SigningServer.Android.IO.ByteBuffer buf = SigningServer.Android.IO.ByteBuffer.Wrap("abcdefgh".GetBytes(SigningServer.Android.IO.Charset.StandardCharsets.UTF_8));
            buf.Position(1);
            buf.Limit(4);
            Com.Android.Apksig.Util.DataSource ds = Com.Android.Apksig.Util.DataSources.AsDataSource(buf);
            buf.Position(2);
            buf.Limit(buf.Capacity());
            SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferEquals("bcd", ds, 0, (int)ds.Size());
            SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("bcd", ds, 0, (int)ds.Size());
            SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("bcd", ds, 0, (int)ds.Size());
            SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("bcd", ds, 0, (int)ds.Size());
        }
        
        protected override SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource CreateDataSource(byte[] contents)
        {
            return SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource.Of(Com.Android.Apksig.Util.DataSources.AsDataSource(SigningServer.Android.IO.ByteBuffer.Wrap(contents)));
        }
        
    }
    
}
