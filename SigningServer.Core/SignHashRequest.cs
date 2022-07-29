using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Core;

/// <summary>
/// Describes a request to sign a hash.
/// </summary>
public class SignHashRequest
{
    /// <summary>
    /// Gets or sets the input hash bytes.
    /// </summary>
    public byte[] InputHash { get; set; }

    /// <summary>
    /// Gets or sets the certificate used during the signing operation.
    /// </summary>
    public X509Certificate2 Certificate { get; set; }

    /// <summary>
    /// Gets or sets the private key used for performing the signing operations.
    /// This key must match the <see cref="Certificate"/> to avoid corrupt signatures.
    /// </summary>
    public AsymmetricAlgorithm PrivateKey { get; set; }

    /// <summary>
    /// Gets or sets the name of the hash algorithm to be used for the signatures.
    /// </summary>
    public string HashAlgorithm { get; set; }
}
