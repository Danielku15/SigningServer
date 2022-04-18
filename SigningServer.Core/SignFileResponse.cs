using System.Collections.Generic;

namespace SigningServer.Core;

/// <summary>
/// Describes the result of a signing operation.
/// </summary>
public class SignFileResponse
{
    /// <summary>
    /// The result status of the signing
    /// </summary>
    public SignFileResponseStatus Status { get; set; }

    /// <summary>
    /// The detailed error message in case <see cref="Status"/> is set to <see cref="SignFileResponseStatus.FileNotSignedError"/>
    /// </summary>
    public string ErrorMessage { get; set; }

    /// <summary>
    /// The result files consisting typically of the signed file.
    /// In some scenarios additional files might be provided (e.g. Android v4 idsig)
    /// </summary>
    public IList<SignFileResponseFileInfo> ResultFiles { get; set; } 
}
