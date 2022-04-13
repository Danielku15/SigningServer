// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Util
{
    /// <summary>
    /// Base class for testing implementations of {@link DataSource}. This class tests the contract of
    /// {@code DataSource}.
    /// 
    /// &lt;p&gt;To subclass, provide an implementation of {@link #createDataSource(byte[])} which returns
    /// the implementation of {@code DataSource} you want to test.
    /// </summary>
    public abstract class DataSourceTestBase: SigningServer.Android.TestBase
    {
        /// <summary>
        /// Returns a new {@link DataSource} containing the provided contents.
        /// </summary>
        protected abstract SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource CreateDataSource(sbyte[] contents);
        
        protected virtual SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource CreateDataSource(string contents)
        {
            return CreateDataSource(contents.GetBytes(SigningServer.Android.IO.Charset.StandardCharsets.UTF_8));
        }
        
        [Test]
        public virtual void TestSize()
        {
            using(SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource c = CreateDataSource("Hello12345"))
            {
                Com.Android.Apksig.Util.DataSource ds = c.GetDataSource();
                AssertEquals(10, ds.Size());
            }
        }
        
        [Test]
        public virtual void TestSlice()
        {
            using(SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource c = CreateDataSource("Hello12345"))
            {
                Com.Android.Apksig.Util.DataSource ds = c.GetDataSource();
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("123", ds, 5, 3);
                Com.Android.Apksig.Util.DataSource slice = ds.Slice(3, 5);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferEquals("lo123", slice, 0, 5);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", ds, 0, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", ds, 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", ds, ds.Size() - 2, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", ds, ds.Size() - 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", ds, ds.Size(), 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", slice, 0, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", slice, 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", slice, slice.Size() - 2, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", slice, slice.Size() - 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("", slice, slice.Size(), 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(ds, -1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(slice, -1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(ds, -1, 2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(slice, -1, 2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(ds, -1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(slice, -1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(ds, 1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(slice, 1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(ds, ds.Size() + 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(slice, slice.Size() + 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(ds, ds.Size(), 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(slice, slice.Size(), 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(ds, ds.Size() - 1, -1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceThrowsIOOB(ds, slice.Size() - 1, -1);
            }
        }
        
        [Test]
        public virtual void TestGetByteBuffer()
        {
            using(SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource c = CreateDataSource("test1234"))
            {
                Com.Android.Apksig.Util.DataSource ds = c.GetDataSource();
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferEquals("s", ds, 2, 1);
                Com.Android.Apksig.Util.DataSource slice = ds.Slice(3, 4);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferEquals("2", slice, 2, 1);
                AssertEquals(0, ds.GetByteBuffer(0, 0).Capacity());
                AssertEquals(0, ds.GetByteBuffer(ds.Size(), 0).Capacity());
                AssertEquals(0, ds.GetByteBuffer(ds.Size() - 1, 0).Capacity());
                AssertEquals(0, ds.GetByteBuffer(ds.Size() - 2, 0).Capacity());
                AssertEquals(0, slice.GetByteBuffer(0, 0).Capacity());
                AssertEquals(0, slice.GetByteBuffer(slice.Size(), 0).Capacity());
                AssertEquals(0, slice.GetByteBuffer(slice.Size() - 1, 0).Capacity());
                AssertEquals(0, slice.GetByteBuffer(slice.Size() - 2, 0).Capacity());
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(ds, -1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(slice, -1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(ds, -1, 2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(slice, -1, 2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(ds, -1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(slice, -1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(ds, 1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(slice, 1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(ds, ds.Size() + 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(slice, slice.Size() + 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(ds, ds.Size(), 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(slice, slice.Size(), 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(ds, ds.Size() - 1, -1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferThrowsIOOB(ds, slice.Size() - 1, -1);
            }
        }
        
        [Test]
        public virtual void TestFeed()
        {
            using(SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource c = CreateDataSource("test1234"))
            {
                Com.Android.Apksig.Util.DataSource ds = c.GetDataSource();
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("23", ds, 5, 2);
                Com.Android.Apksig.Util.DataSource slice = ds.Slice(1, 5);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("t", slice, 2, 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", ds, 0, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", ds, 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", ds, ds.Size() - 2, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", ds, ds.Size() - 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", ds, ds.Size(), 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", slice, 0, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", slice, 2, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", slice, slice.Size() - 2, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", slice, slice.Size() - 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("", slice, slice.Size(), 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(ds, -1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(slice, -1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(ds, -1, 2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(slice, -1, 2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(ds, -1, 10);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(slice, -1, 10);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(ds, 1, 10);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(slice, 1, 10);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(ds, ds.Size() + 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(slice, slice.Size() + 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(ds, ds.Size(), 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(slice, slice.Size(), 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(ds, ds.Size() - 1, -1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedThrowsIOOB(ds, slice.Size() - 1, -1);
            }
        }
        
        [Test]
        public virtual void TestCopyTo()
        {
            using(SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource c = CreateDataSource("abcdefghijklmnop"))
            {
                Com.Android.Apksig.Util.DataSource ds = c.GetDataSource();
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("fgh", ds, 5, 3);
                Com.Android.Apksig.Util.DataSource slice = ds.Slice(2, 7);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("efgh", slice, 2, 4);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", ds, 0, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", ds, 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", ds, ds.Size() - 2, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", ds, ds.Size() - 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", ds, ds.Size(), 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", slice, 0, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", slice, 2, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", slice, slice.Size() - 2, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", slice, slice.Size() - 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("", slice, slice.Size(), 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(ds, -1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(slice, -1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(ds, -1, 2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(slice, -1, 2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(ds, -1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(slice, -1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(ds, 1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(slice, 1, 20);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(ds, ds.Size() + 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(slice, slice.Size() + 1, 0);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(ds, ds.Size(), 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(slice, slice.Size(), 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(ds, ds.Size() - 1, -1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsIOOB(ds, slice.Size() - 1, -1);
                SigningServer.Android.IO.ByteBuffer buf = SigningServer.Android.IO.ByteBuffer.Allocate(5);
                buf.Position(2);
                buf.Limit(3);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsBufferOverflow(ds, 0, 2, buf);
                buf.Position(2);
                buf.Limit(3);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToThrowsBufferOverflow(slice, 1, 2, buf);
                buf = SigningServer.Android.IO.ByteBuffer.Allocate(10);
                buf.Position(2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("bcd", ds, 1, 3, buf);
                buf = SigningServer.Android.IO.ByteBuffer.Allocate(10);
                buf.Position(2);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("fg", slice, 3, 2, buf);
            }
        }
        
        protected static void AssertSliceEquals(string expectedContents, Com.Android.Apksig.Util.DataSource ds, long offset, int size)
        {
            Com.Android.Apksig.Util.DataSource slice = ds.Slice(offset, size);
            AssertEquals(size, slice.Size());
            SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferEquals(expectedContents, slice, 0, size);
        }
        
        protected static void AssertSliceThrowsIOOB(Com.Android.Apksig.Util.DataSource ds, long offset, int size)
        {
            try
            {
                ds.Slice(offset, size);
                Fail();
            }
            catch (System.IndexOutOfRangeException expected)
            {
            }
        }
        
        protected static void AssertGetByteBufferEquals(string expectedContents, Com.Android.Apksig.Util.DataSource ds, long offset, int size)
        {
            SigningServer.Android.IO.ByteBuffer buf = ds.GetByteBuffer(offset, size);
            AssertEquals(0, buf.Position());
            AssertEquals(size, buf.Limit());
            AssertEquals(size, buf.Capacity());
            AssertEquals(expectedContents, SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.ToString(buf));
        }
        
        protected static void AssertGetByteBufferThrowsIOOB(Com.Android.Apksig.Util.DataSource ds, long offset, int size)
        {
            try
            {
                ds.GetByteBuffer(offset, size);
                Fail();
            }
            catch (System.IndexOutOfRangeException expected)
            {
            }
        }
        
        protected static void AssertFeedEquals(string expectedFedContents, Com.Android.Apksig.Util.DataSource ds, long offset, int size)
        {
            Com.Android.Apksig.Util.ReadableDataSink output = Com.Android.Apksig.Util.DataSinks.NewInMemoryDataSink(size);
            ds.Feed(offset, size, output);
            AssertEquals(size, output.Size());
            AssertEquals(expectedFedContents, SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.ToString(output.GetByteBuffer(0, size)));
        }
        
        protected static void AssertFeedThrowsIOOB(Com.Android.Apksig.Util.DataSource ds, long offset, long size)
        {
            try
            {
                ds.Feed(offset, size, SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.NullDataSink.INSTANCE);
                Fail();
            }
            catch (System.IndexOutOfRangeException expected)
            {
            }
        }
        
        protected static void AssertCopyToEquals(string expectedContents, Com.Android.Apksig.Util.DataSource ds, long offset, int size)
        {
            sbyte[] arr = new sbyte[size + 10];
            SigningServer.Android.IO.ByteBuffer buf = SigningServer.Android.IO.ByteBuffer.Wrap(arr, 1, size + 5);
            buf.Position(2);
            AssertEquals(size + 4, buf.Remaining());
            SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals(expectedContents, ds, offset, size, buf);
        }
        
        internal static void AssertCopyToEquals(string expectedContents, Com.Android.Apksig.Util.DataSource ds, long offset, int size, SigningServer.Android.IO.ByteBuffer buf)
        {
            int oldPosition = buf.Position();
            int oldLimit = buf.Limit();
            ds.CopyTo(offset, size, buf);
            AssertEquals(oldPosition + size, buf.Position());
            AssertEquals(oldLimit, buf.Limit());
            buf.Limit(buf.Position());
            buf.Position(oldPosition);
            AssertEquals(expectedContents, SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.ToString(buf));
        }
        
        protected static void AssertCopyToThrowsIOOB(Com.Android.Apksig.Util.DataSource ds, long offset, int size)
        {
            SigningServer.Android.IO.ByteBuffer buf = SigningServer.Android.IO.ByteBuffer.Allocate((size < 0) ? 0 : size);
            try
            {
                ds.CopyTo(offset, size, buf);
                Fail();
            }
            catch (System.IndexOutOfRangeException expected)
            {
            }
        }
        
        internal static void AssertCopyToThrowsBufferOverflow(Com.Android.Apksig.Util.DataSource ds, long offset, int size, SigningServer.Android.IO.ByteBuffer buf)
        {
            try
            {
                ds.CopyTo(offset, size, buf);
                Fail();
            }
            catch (SigningServer.Android.IO.BufferOverflowException expected)
            {
            }
        }
        
        /// <summary>
        /// Returns the contents of the provided buffer as a string. The buffer's position and limit
        /// remain unchanged.
        /// </summary>
        public static string ToString(SigningServer.Android.IO.ByteBuffer buf)
        {
            sbyte[] arr;
            int offset;
            int size = buf.Remaining();
            if (buf.HasArray())
            {
                arr = buf.Array();
                offset = buf.ArrayOffset() + buf.Position();
            }
            else 
            {
                arr = new sbyte[buf.Remaining()];
                offset = 0;
                int oldPos = buf.Position();
                buf.Get(arr);
                buf.Position(oldPos);
            }
            return SigningServer.Android.Core.StringExtensions.Create(arr, offset, size, SigningServer.Android.IO.Charset.StandardCharsets.UTF_8);
        }
        
        public class CloseableWithDataSource: SigningServer.Android.TestBase, System.IDisposable
        {
            internal readonly Com.Android.Apksig.Util.DataSource mDataSource;
            
            internal readonly System.IDisposable mCloseable;
            
            internal CloseableWithDataSource(Com.Android.Apksig.Util.DataSource dataSource, System.IDisposable closeable)
            {
                mDataSource = dataSource;
                mCloseable = closeable;
            }
            
            public static SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource Of(Com.Android.Apksig.Util.DataSource dataSource)
            {
                return new SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource(dataSource, null);
            }
            
            public static SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource Of(Com.Android.Apksig.Util.DataSource dataSource, System.IDisposable closeable)
            {
                return new SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource(dataSource, closeable);
            }
            
            public virtual Com.Android.Apksig.Util.DataSource GetDataSource()
            {
                return mDataSource;
            }
            
            public virtual System.IDisposable GetCloseable()
            {
                return mCloseable;
            }
            
            public override void Close()
            {
                if (mCloseable != null)
                {
                    mCloseable.Dispose();
                }
            }
            
        }
        
        internal class NullDataSink: SigningServer.Android.TestBase, Com.Android.Apksig.Util.DataSink
        {
            internal static readonly SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.NullDataSink INSTANCE = new SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.NullDataSink();
            
            public override void Consume(sbyte[] buf, int offset, int length)
            {
            }
            
            public override void Consume(SigningServer.Android.IO.ByteBuffer buf)
            {
            }
            
        }
        
    }
    
}
