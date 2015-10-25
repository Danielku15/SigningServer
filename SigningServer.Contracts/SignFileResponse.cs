using System;
using System.IO;
using System.ServiceModel;

namespace SigningServer.Contracts
{
    [MessageContract]
    public class SignFileResponse : IDisposable
    {
        /// <summary>
        /// The result of the signing
        /// </summary>
        [MessageHeader]
        public SignFileResponseResult Result { get; set; }
        /// <summary>
        /// The detailed error message in case <see cref="Result"/> is set to <see cref="SignFileResponseResult.FileNotSignedError"/>
        /// </summary>
        [MessageHeader]
        public string ErrorMessage { get; set; }
        /// <summary>
        /// The size of the signed file in bytes.
        /// </summary>
        [MessageHeader]
        public long FileSize { get; set; }
        /// <summary>
        /// The signed file. 
        /// </summary>
        [MessageBodyMember]
        public Stream FileContent { get; set; }

        public void Dispose()
        {
            if (FileContent != null)
            {
                var fileName = FileContent is FileStream ? ((FileStream) FileContent).Name : "";
                FileContent.Dispose();
                FileContent = null;
                if (!string.IsNullOrWhiteSpace(fileName) && File.Exists(fileName))
                {
                    File.Delete(fileName);
                }
            }
        }

        public override string ToString()
        {
            return $"Result: {Result}, ErrorMessage: {ErrorMessage}, FileSize: {FileSize}";
        }
    }
}