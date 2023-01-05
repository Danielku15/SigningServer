using System.Security.Cryptography.X509Certificates;

namespace SigningServer.Server.Dtos;

public class LoadCertificateRequestDto
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
    /// The format into which the certificates will be encoded.
    /// </summary>
    public X509ContentType ExportFormat { get; set; }

    /// <summary>
    /// Whether to include the full certificate chain.
    /// </summary>
    public bool IncludeChain { get; set; }
}
