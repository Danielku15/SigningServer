using SigningServer.Core;

namespace SigningServer.Server.Dtos;

/// <summary>
/// 
/// </summary>
/// <param name="Status">The result of the certificate loading</param>
/// <param name="ErrorMessage">The detailed error message in case <see cref="Status"/> is set to <see cref="LoadCertificateResponseStatus.CertificateNotLoadedError"/></param>
/// <param name="CertificateData"> The base64 encoded certificate bytes.</param>
public record LoadCertificateResponseDto(
    LoadCertificateResponseStatus Status,
    string? ErrorMessage,
    string? CertificateData
);
