using System.ComponentModel.DataAnnotations;

namespace SigningServer.Server.Dtos;

public class SignHashRequestDto
{
    /// <summary>
    /// The username to authenticate the signing
    /// </summary>
    public string Username { get; set; }

    /// <summary>
    /// The SHA2 hash of the password to authenticate the signing.
    /// </summary>
    public string Password { get; set; }

    /// <summary>
    /// The hash algorithm to use for signing
    /// </summary>
    [Required]
    public string HashAlgorithm { get; set; }

    /// <summary>
    /// The hex encoded raw hash bytes to sign.
    /// </summary>
    [Required]
    public string Hash { get; set; }
}
