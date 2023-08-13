using Microsoft.AspNetCore.Http;
using SigningServer.Core;

namespace SigningServer.Server.Dtos;

public class SignFileResponseDto
{
    /// <summary>
    /// The result of the signing
    /// </summary>
    public SignFileResponseStatus Status { get; set; }

    /// <summary>
    /// The number of milliseconds it took to fully accept the file
    /// (starting from when the request was received).
    /// </summary>
    public long UploadTimeInMilliseconds { get; set; }

    /// <summary>
    /// The number of milliseconds it took to effectively sign the file.
    /// </summary>
    public long SignTimeInMilliseconds { get; set; }

    /// <summary>
    /// The detailed error message in case <see cref="Status"/> is set to <see cref="SignFileResponseStatus.FileNotSignedError"/>
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// The result files consisting typically of the signed file.
    /// In some scenarios additional files might be provided (e.g. Android v4 idsig)
    /// </summary>
    public IFormFileCollection? ResultFiles { get; set; } // Mainly used for documentation purposes, SignFileActionResult handles the serialization
}
