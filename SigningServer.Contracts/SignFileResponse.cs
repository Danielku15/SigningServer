using System;
using System.IO;
using System.ServiceModel;

namespace SigningServer.Contracts;

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

    public SignFileResponse()
    {
        FileContent = new MemoryStream();
    }

    public void Dispose()
    {
        if (FileContent != null)
        {
            var fileName = FileContent is FileStream stream ? stream.Name : "";
            try
            {
                FileContent.Dispose();
                FileContent = null;
            }
            catch
            {
                // ignored
            }

            if (!string.IsNullOrWhiteSpace(fileName) && File.Exists(fileName))
            {
                try
                {
                    File.Delete(fileName);
                    DeleteSuccess?.Invoke(this, fileName);
                }
                catch (Exception e)
                {
                    DeleteFailed?.Invoke(this, fileName, e);
                }
            }
            else
            {
                DeleteSkipped?.Invoke(this, fileName);
            }
        }
    }

    public event Action<SignFileResponse, string> DeleteSkipped;
    public event Action<SignFileResponse, string> DeleteSuccess;
    public event Action<SignFileResponse, string, Exception> DeleteFailed;

    public override string ToString()
    {
        return $"Result: {Result}, ErrorMessage: {ErrorMessage}, FileSize: {FileSize}";
    }
}
