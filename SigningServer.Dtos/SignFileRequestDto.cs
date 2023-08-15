namespace SigningServer.Dtos;

public class SignFileRequestDto
{
    /// <summary>
    /// The username to authenticate the signing
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// The SHA2 hash of the password to authenticate the signing.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// If the input file is already signed, signing will be skipped unless this flag is set. 
    /// </summary>
    public bool OverwriteSignature { get; set; }

    /// <summary>
    /// The hash algorithm to use for signing
    /// </summary>
    public string? HashAlgorithm { get; set; }
}
