// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Test
{
    public abstract class MoreAsserts: SigningServer.Android.TestBase
    {
        internal MoreAsserts()
        {
        }
        
        /// <summary>
        /// Asserts that the contents of the provided {@code ByteBuffer} are as expected. This method
        /// does not change the position or the limit of the provided buffer.
        /// </summary>
        public static void AssertByteBufferEquals(byte[] expected, SigningServer.Android.IO.ByteBuffer actual)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Test.MoreAsserts.AssertByteBufferEquals(null, expected, actual);
        }
        
        /// <summary>
        /// Asserts that the contents of the provided {@code ByteBuffer} are as expected. This method
        /// does not change the position or the limit of the provided buffer.
        /// </summary>
        public static void AssertByteBufferEquals(string message, byte[] expected, SigningServer.Android.IO.ByteBuffer actual)
        {
            byte[] actualArr;
            if ((actual.HasArray()) && (actual.ArrayOffset() == 0) && (actual.Array().Length == actual.Remaining()))
            {
                actualArr = actual.Array();
            }
            else 
            {
                actualArr = new byte[actual.Remaining()];
                int actualOriginalPos = actual.Position();
                actual.Get(actualArr);
                actual.Position(actualOriginalPos);
            }
            AssertArrayEquals(message, expected, actualArr);
        }
        
    }
    
}
