using SigningServer.Core;

namespace SigningServer.Server.Dtos;

public class SignHashResponseDto
{
    /// <summary>
    /// The result of the signing
    /// </summary>
    public SignHashResponseStatus Status { get; set; }

    /// <summary>
    /// The number of milliseconds it took to effectively sign the file.
    /// </summary>
    public long SignTimeInMilliseconds { get; set; }

    /// <summary>
    /// The detailed error message in case <see cref="Status"/> is set to <see cref="SignHashResponseStatus.HashNotSignedError"/>
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// The hex encoded signature bytes of the signed hash.
    /// </summary>
    public string Signature { get; set; } = string.Empty;
}
