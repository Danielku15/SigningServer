using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace SigningServer.Dtos;

public class SignHashRequestDto
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
    /// The hash algorithm to use for signing
    /// </summary>
    [Required]
    public string HashAlgorithm { get; set; } = string.Empty;

    /// <summary>
    /// The padding algorithm to use for signing
    /// </summary>
    public RSASignaturePaddingMode? PaddingMode { get; set; }

    /// <summary>
    /// The base64 encoded raw hash bytes to sign.
    /// </summary>
    [Required]
    public string Hash { get; set; } = string.Empty;
}
