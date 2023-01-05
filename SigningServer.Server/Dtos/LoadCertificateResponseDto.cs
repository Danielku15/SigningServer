using SigningServer.Core;

namespace SigningServer.Server.Dtos;

public class LoadCertificateResponseDto
{
    /// <summary>
    /// The result of the signing
    /// </summary>
    public LoadCertificateResponseStatus Status { get; set; }

    /// <summary>
    /// The detailed error message in case <see cref="Status"/> is set to <see cref="LoadCertificateResponseStatus.CertificateNotLoadedError"/>
    /// </summary>
    public string ErrorMessage { get; set; }

    /// <summary>
    /// The base64 encoded certificate bytes.
    /// </summary>
    public string CertificateData { get; set; }
}
