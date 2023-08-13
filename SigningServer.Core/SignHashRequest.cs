using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Core;

/// <summary>
/// Describes a request to sign a hash.
/// </summary>
/// <param name="InputHash">The input hash bytes</param>
/// <param name="Certificate">The certificate used during the signing operation</param>
/// <param name="PrivateKey">
/// The private key used for performing the signing operations.
/// This key must match the <see cref="Certificate"/> to avoid corrupt signatures.
/// </param>
/// <param name="HashAlgorithm">The name of the hash algorithm to be used for the signatures</param>
public record SignHashRequest(
    byte[] InputHash,
    X509Certificate2 Certificate,
    AsymmetricAlgorithm PrivateKey,
    string HashAlgorithm
);
