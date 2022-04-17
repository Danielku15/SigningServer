using System;
using System.IO;
using System.ServiceModel;

namespace SigningServer.Contracts;

[MessageContract]
public class SignFileRequest : IDisposable
{
    /// <summary>
    /// The username to authenticate the signing
    /// </summary>
    [MessageHeader]
    public string Username { get; set; }
    /// <summary>
    /// The SHA2 hash of the password to authenticate the signing.
    /// </summary>
    [MessageHeader]
    public string Password { get; set; }
    /// <summary>
    /// The filename of the file to be signed.
    /// </summary>
    [MessageHeader]
    public string FileName { get; set; }
    /// <summary>
    /// If the input file is already signed, signing will be skipped unless this flag is set. 
    /// </summary>
    [MessageHeader]
    public bool OverwriteSignature { get; set; }
    /// <summary>
    /// The file size in bytes.
    /// </summary>
    [MessageHeader]
    public long FileSize { get; set; }
    /// <summary>
    /// The file contents.
    /// </summary>
    [MessageBodyMember]
    public Stream FileContent { get; set; }
    /// <summary>
    /// The hash algorithm to use for signing
    /// </summary>
    [MessageHeader]
    public string HashAlgorithm { get; set; }

    public void Dispose()
    {
        if (FileContent != null)
        {
            FileContent.Dispose();
            FileContent = null;
        }
    }
}