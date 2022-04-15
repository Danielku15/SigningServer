// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Apk
{
    /// <summary>
    /// APK Signature Scheme block and additional information relevant to verifying the signatures
    /// contained in the block against the file.
    /// </summary>
    public class SignatureInfo
    {
        /// <summary>
        /// Contents of APK Signature Scheme block.
        /// </summary>
        public readonly SigningServer.Android.IO.ByteBuffer signatureBlock;
        
        /// <summary>
        /// Position of the APK Signing Block in the file.
        /// </summary>
        public readonly long apkSigningBlockOffset;
        
        /// <summary>
        /// Position of the ZIP Central Directory in the file.
        /// </summary>
        public readonly long centralDirOffset;
        
        /// <summary>
        /// Position of the ZIP End of Central Directory (EoCD) in the file.
        /// </summary>
        public readonly long eocdOffset;
        
        /// <summary>
        /// Contents of ZIP End of Central Directory (EoCD) of the file.
        /// </summary>
        public readonly SigningServer.Android.IO.ByteBuffer eocd;
        
        public SignatureInfo(SigningServer.Android.IO.ByteBuffer signatureBlock, long apkSigningBlockOffset, long centralDirOffset, long eocdOffset, SigningServer.Android.IO.ByteBuffer eocd)
        {
            this.signatureBlock = signatureBlock;
            this.apkSigningBlockOffset = apkSigningBlockOffset;
            this.centralDirOffset = centralDirOffset;
            this.eocdOffset = eocdOffset;
            this.eocd = eocd;
        }
        
    }
    
}