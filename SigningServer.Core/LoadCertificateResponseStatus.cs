namespace SigningServer.Core;

/// <summary>
/// Lists the different formats to load the certificate
/// </summary>
public enum LoadCertificateFormat
{
    /// <summary>
    /// A PEM encoded file with the whole certificate (CERTIFICATE sections)
    /// </summary>
    PemCertificate,
    /// <summary>
    /// A PEM encoded file with the public keys only (PUBLIC KEY sections)
    /// </summary>
    PemPublicKey,
    /// <summary>
    /// A Pkcs12 (aka. PFX) container.
    /// </summary>
    Pkcs12
}

/// <summary>
/// Lists all possible result status codes of a certificate loading operation.
/// </summary>
public enum LoadCertificateResponseStatus
{
    /// <summary>
    /// Certificate was successfully loaded
    /// </summary>
    CertificateLoaded,

    /// <summary>
    /// The certificate could not be loaded because an unexpected error happened.
    /// </summary>
    CertificateNotLoadedError,

    /// <summary>
    /// The certificate could not be loaded because the singing request was noth authorized.
    /// </summary>
    CertificateNotLoadedUnauthorized
}
