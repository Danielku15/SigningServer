namespace SigningServer.Core;

/// <summary>
/// Describes the result of a hash signing operation.
/// </summary>
public class SignHashResponse
{
    /// <summary>
    /// The result status of the signing
    /// </summary>
    public SignHashResponseStatus Status { get; set; }

    /// <summary>
    /// The detailed error message in case <see cref="Status"/> is set to <see cref="SignHashResponseStatus.HashNotSignedError"/>
    /// </summary>
    public string ErrorMessage { get; set; }

    /// <summary>
    /// The resulting signature of the provided hash.
    /// </summary>
    public byte[] Signature { get; set; } 
}
