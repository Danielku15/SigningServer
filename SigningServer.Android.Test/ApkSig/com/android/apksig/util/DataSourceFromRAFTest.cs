// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Util
{
    /// <summary>
    /// Tests for the {@link DataSource} returned by
    /// {@link DataSources#asDataSource(java.io.RandomAccessFile)}.
    /// </summary>
    [RunWith(typeof(var))]
    public class DataSourceFromRAFTest: SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase
    {
        [Parameterized.Parameters(Name = "{0}")]
        public static SigningServer.Android.Com.Android.Apksig.Util.DataSourceFromRAFFactory[] Data()
        {
            return DataSourceFromRAFFactory.Values();
        }
        
        [Parameterized.Parameter]
        public SigningServer.Android.Com.Android.Apksig.Util.DataSourceFromRAFFactory factory;
        
        [Test]
        public virtual void TestFileSizeChangesVisible()
        {
            using(SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource c = CreateDataSource("abcdefg"))
            {
                Com.Android.Apksig.Util.DataSource ds = c.GetDataSource();
                Com.Android.Apksig.Util.DataSource slice = ds.Slice(3, 2);
                System.IO.FileInfo f = ((SigningServer.Android.Com.Android.Apksig.Util.DataSourceFromRAFTest.TmpFileCloseable)c.GetCloseable()).GetFile();
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferEquals("abcdefg", ds, 0, (int)ds.Size());
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferEquals("de", slice, 0, (int)slice.Size());
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("cdefg", ds, 2, 5);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("e", slice, 1, 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("cdefg", ds, 2, 5);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("e", slice, 1, 1);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("cdefg", ds, 2, 5);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("e", slice, 1, 1);
                using(SigningServer.Android.IO.RandomAccessFile raf = new SigningServer.Android.IO.RandomAccessFile(f, "rw"))
                {
                    raf.Seek(7);
                    raf.Write("hijkl".GetBytes(SigningServer.Android.IO.Charset.StandardCharsets.UTF_8));
                }
                AssertEquals(12, ds.Size());
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferEquals("abcdefghijkl", ds, 0, (int)ds.Size());
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertGetByteBufferEquals("de", slice, 0, (int)slice.Size());
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("cdefg", ds, 2, 5);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertFeedEquals("fgh", ds, 5, 3);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertCopyToEquals("fgh", ds, 5, 3);
                SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.AssertSliceEquals("fgh", ds, 5, 3);
            }
        }
        
        protected override SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource CreateDataSource(sbyte[] contents)
        {
            System.IO.FileInfo tmp = System.IO.FileInfo.CreateTempFile(typeof(SigningServer.Android.Com.Android.Apksig.Util.DataSourceFromRAFTest).GetSimpleName(), ".bin");
            SigningServer.Android.IO.RandomAccessFile f = null;
            try
            {
                SigningServer.Android.IO.File.Files.Write(tmp.ToPath(), contents);
                f = new SigningServer.Android.IO.RandomAccessFile(tmp, "r");
            }
            finally
            {
                if (f == null)
                {
                    tmp.Delete();
                }
            }
            return SigningServer.Android.Com.Android.Apksig.Util.DataSourceTestBase.CloseableWithDataSource.Of(factory.Create(f), new SigningServer.Android.Com.Android.Apksig.Util.DataSourceFromRAFTest.TmpFileCloseable(tmp, f));
        }
        
        /// <summary>
        /// {@link Closeable} which closes the delegate {@code Closeable} and deletes the provided file.
        /// </summary>
        internal class TmpFileCloseable: System.IDisposable
        {
            internal readonly System.IO.FileInfo mFile;
            
            internal readonly System.IDisposable mDelegate;
            
            internal TmpFileCloseable(System.IO.FileInfo file, System.IDisposable closeable)
            {
                mFile = file;
                mDelegate = closeable;
            }
            
            public virtual System.IO.FileInfo GetFile()
            {
                return mFile;
            }
            
            public override void Close()
            {
                try
                {
                    if (mDelegate != null)
                    {
                        mDelegate.Dispose();
                    }
                }
                finally
                {
                    if (mFile != null)
                    {
                        mFile.Delete();
                    }
                }
            }
            
        }
        
    }
    
}
