using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Core;

/// <summary>
/// Describes a request to sign a file.
/// </summary>
/// <param name="InputFilePath">The absolute path to the file being signed</param>
/// <param name="Certificate">The certificate used during the signing operation. Typically embedded into the signed file (without private keys).</param>
/// <param name="PrivateKey">The private key used for performing the signing operations. This key must match the <see cref="Certificate"/> to avoid corrupt signatures.</param>
/// <param name="OriginalFileName">
/// The original name of the file being signed. <see cref="InputFilePath"/>
/// might point to a temporarily name while <see cref="OriginalFileName"/> is the name of
/// the file as provided by the client. Might be used to generate auxiliary files.
/// </param>
/// <param name="TimestampServer">The timestamping server which should be used for timestamping the signatures</param>
/// <param name="HashAlgorithm">The name of the hash algorithm to be used for the signatures</param>
/// <param name="OverwriteSignature">Whether any existing signatures should be overwritten.
/// If this is not set, and a file is already signed, the signing operation will fail.</param>
public record SignFileRequest(
    string InputFilePath,
    Lazy<X509Certificate2> Certificate,
    Lazy<AsymmetricAlgorithm> PrivateKey,
    string OriginalFileName,
    string TimestampServer,
    string? HashAlgorithm,
    bool OverwriteSignature
);
