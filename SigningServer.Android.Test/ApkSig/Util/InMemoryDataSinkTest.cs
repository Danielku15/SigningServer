using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.Android.ApkSig.Util;

namespace SigningServer.Android.Test.ApkSig.Util
{
    [TestClass]
    public class InMemoryDataSinkTest : DataSinkTestBase<ReadableDataSink>
    {
        protected override CloseableWithDataSink createDataSink()
        {
            return CloseableWithDataSink.of(DataSinks.newInMemoryDataSink());
        }

        protected override ByteBuffer getContents(ReadableDataSink dataSink)
        {
            if (dataSink.size() > int.MaxValue)
            {
                throw new IOException("Too much data: " + dataSink.size());
            }

            return dataSink.getByteBuffer(0, (int)dataSink.size());
        }
    }
}