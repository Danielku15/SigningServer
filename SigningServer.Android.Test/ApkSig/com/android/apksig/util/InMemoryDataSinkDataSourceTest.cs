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
    /// Tests for the {@link DataSource} returned by {@link DataSinks#newInMemoryDataSink()}.
    /// </summary>
    [TestClass]
    public class InMemoryDataSinkDataSourceTest: SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase
    {
        protected override SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource CreateDataSource(sbyte[] contents)
        {
            Com.Android.Apksig.Util.ReadableDataSink sink = Com.Android.Apksig.Util.DataSinks.NewInMemoryDataSink();
            sink.Consume(contents, 0, contents.Length);
            return SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource.Of(sink);
        }
        
    }
    
}
